"""Incremental, query-ready cache for Red Hat's public CSAF VEX feed."""

import concurrent.futures
import contextlib
import csv
import fcntl
import io
import json
import re
import sqlite3
import sys
import tarfile
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# The GA feed is binary-RPM aware.  The older ``vex`` endpoint remains public
# for compatibility, but does not carry the current component expansion.
VEX_BASE_URL = "https://security.access.redhat.com/data/csaf/v2/vex-feed/"
VEX_ARCHIVE_URL = VEX_BASE_URL + "vex-archive.tar.zst"
SYNC_LOCK_TIMEOUT_SECONDS = 600
ARCHIVE_CATCHUP_WORKERS = 24
CACHE_SCHEMA_VERSION = "4"
DOCUMENT_FETCH_ATTEMPTS = 5

try:  # Python 3.14+; older interpreters use the incremental document fallback.
    from compression import zstd
except ImportError:  # pragma: no cover - depends on the user's Python version.
    zstd = None


def _request(url, accept="application/json"):
    request = urllib.request.Request(url, headers={"User-Agent": "cve-report/1.0", "Accept": accept})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read().decode("utf-8")


def _canonical_uri(uri):
    """Normalize public CVE document paths across feed case-only churn."""
    uri = uri.removeprefix("./").removeprefix("vex-feed/")
    match = re.fullmatch(r"(\d{4})/(cve-\d{4}-\d+\.json)", uri, re.IGNORECASE)
    if match:
        return f"{match.group(1)}/{match.group(2).lower()}"
    return uri


def _archive_documents(remote):
    """Stream the published full feed archive without staging it on disk."""
    if zstd is None:
        raise RuntimeError("Python 3.14+ is required for archive-backed VEX initialization")
    request = urllib.request.Request(VEX_ARCHIVE_URL, headers={"User-Agent": "cve-report/1.0"})
    with urllib.request.urlopen(request, timeout=600) as response:
        with zstd.open(response, "rb") as decompressed:
            with tarfile.open(fileobj=decompressed, mode="r|") as archive:
                for member in archive:
                    if not member.isfile() or not member.name.endswith(".json"):
                        continue
                    uri = _canonical_uri(member.name)
                    if uri not in remote:
                        continue
                    document = json.load(archive.extractfile(member))
                    yield uri, remote[uri], document


def _connect(cache_path):
    Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(cache_path, timeout=60)
    connection.execute("PRAGMA busy_timeout = 60000")
    connection.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS documents (
            uri TEXT PRIMARY KEY,
            modified TEXT NOT NULL,
            fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS cache_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS unavailable_documents (
            uri TEXT PRIMARY KEY,
            modified TEXT NOT NULL,
            reason TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS rpm_status (
            uri TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            component TEXT NOT NULL,
            evr TEXT NOT NULL DEFAULT '',
            stream TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            disposition TEXT NOT NULL DEFAULT '',
            title TEXT,
            impact TEXT,
            cvss REAL,
            PRIMARY KEY (uri, cve_id, component, evr, stream, status, disposition)
        ) WITHOUT ROWID;
    """)
    _create_indexes(connection)
    return connection


def _discard_cache_files(cache_path):
    """Remove an obsolete derived cache before rebuilding it with the current schema."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{cache_path}{suffix}").unlink(missing_ok=True)


def _create_indexes(connection):
    connection.execute("CREATE INDEX IF NOT EXISTS rpm_status_lookup ON rpm_status(component, stream, status)")


def _begin_bulk_load(connection):
    """Tune a fresh, derived cache for high-throughput archive ingestion."""
    connection.commit()
    connection.execute("PRAGMA synchronous = OFF")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA cache_size = -262144")  # 256 MiB process-local page cache
    connection.execute("DROP INDEX IF EXISTS rpm_status_lookup")


def _finish_bulk_load(connection):
    connection.commit()
    _create_indexes(connection)
    connection.commit()
    connection.execute("PRAGMA synchronous = NORMAL")


def _migrate_schema(connection, cached_schema):
    """Apply non-destructive cache schema migrations used by Update.

    Update is intentionally incremental: it must retain already-indexed CSAF
    documents and request only the records whose feed timestamp changed.  A
    full cache replacement is reserved for the explicit Rebuild operation.
    """
    if cached_schema != ("3",):
        return False
    columns = {row[1] for row in connection.execute("PRAGMA table_info(rpm_status)")}
    if "disposition" not in columns:
        connection.execute("ALTER TABLE rpm_status ADD COLUMN disposition TEXT NOT NULL DEFAULT ''")
    connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('schema_version', ?)",
                       (CACHE_SCHEMA_VERSION,))
    connection.commit()
    return True


@contextlib.contextmanager
def _sync_lock(cache_path, timeout=SYNC_LOCK_TIMEOUT_SECONDS):
    """Serialize cache writers across CLI and local UI processes on macOS/Linux."""
    lock_path = Path(f"{cache_path}.sync.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    waiting = False
    with lock_path.open("a+") as handle:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Timed out waiting for another VEX cache refresh: {cache_path}")
                if not waiting:
                    print("  VEX cache: another refresh is in progress; waiting for its write lock...",
                          file=sys.stderr, flush=True)
                    waiting = True
                time.sleep(1)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _walk_products(branches, products):
    for branch in branches or []:
        product = branch.get("product")
        if product:
            helper = product.get("product_identification_helper", {})
            products[product.get("product_id")] = helper
        _walk_products(branch.get("branches"), products)


def _stream(product_id, helper):
    cpe = helper.get("cpe", "")
    cpe_match = re.search(r"enterprise_linux:(\d+)(?:\.(\d+))?", cpe)
    if cpe_match:
        return f"{cpe_match.group(1)}.{cpe_match.group(2) or '0'}"
    match = re.search(r"(?:BaseOS|AppStream|CRB)-(\d+)\.(\d+)", product_id or "")
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    # Current GA VEX records commonly use stream roots such as
    # ``rhel-10.0.z.eus:curl.src``.  They do not necessarily carry a CPE
    # helper, so recognize the product ID directly rather than dropping a
    # valid RHEL product status during normalization.
    match = re.search(r"(?:^|:)rhel-(\d+)\.(\d+)(?:\.[^:]+)?(?::|$)", product_id or "")
    return f"{match.group(1)}.{match.group(2)}" if match else None


def _component_and_evr(product_id, helper):
    purl = helper.get("purl", "")
    purl_name = purl.rsplit("/", 1)[-1].split("@", 1)[0].split("?", 1)[0]
    payload = product_id.split(":", 1)[1] if ":" in product_id else ""
    payload = payload.split("::", 1)[0].removesuffix(".src")
    parts = payload.rsplit("-", 2)
    if len(parts) == 3 and ":" in parts[1]:
        evr = f"{parts[1]}-{parts[2]}"
        for architecture in ("aarch64", "i686", "noarch", "ppc64le", "s390x", "src", "x86_64"):
            evr = evr.removesuffix(f".{architecture}")
        return parts[0], evr
    return purl_name or payload, None


def _severity(vulnerability):
    for threat in vulnerability.get("threats", []):
        if threat.get("category") == "impact":
            return threat.get("details", "").upper()
    return ""


def _cvss(vulnerability):
    for score in vulnerability.get("scores", []):
        for key, value in score.items():
            if key.startswith("cvss_v") and isinstance(value, dict) and "baseScore" in value:
                return float(value["baseScore"])
    return None


def _remediation_dispositions(vulnerability):
    """Return the public VEX remediation disposition by product ID.

    CSAF status expresses affectedness (for example ``known_affected``),
    while a deferred/no-fix decision lives in ``remediations``.  Keep these
    axes separate: an OSIDB DEFER or DELEGATED affect must never be filtered
    out merely because no vendor fix is currently available.
    """
    dispositions = defaultdict(set)
    for remediation in vulnerability.get("remediations", []):
        category = remediation.get("category", "")
        details = remediation.get("details", "")
        if category == "none_available":
            # Public VEX generally calls this "Affected".  Present the
            # customer-useful disposition rather than pretending it is a
            # distinct CSAF product-status value.
            disposition = "deferred / no fix available"
        elif category == "vendor_fix":
            disposition = "fix available"
        elif category == "workaround":
            disposition = "workaround available"
        else:
            disposition = category or details
        for product_id in remediation.get("product_ids", []):
            dispositions[product_id].add(disposition)
    return dispositions


def _normalized_rows(uri, document, module=None):
    products = {}
    _walk_products(document.get("product_tree", {}).get("branches"), products)
    target_major = module.removeprefix("rhel-") if module else None

    def in_target_stream(product_id, helper):
        stream = _stream(product_id, helper)
        return not target_major or (stream and stream.split(".", 1)[0] == target_major)

    product_rows = [
        (uri, product_id, helper.get("purl", ""), helper.get("cpe", ""), _stream(product_id, helper))
        for product_id, helper in products.items()
        if in_target_stream(product_id, helper)
    ]
    status_rows = []
    rpm_rows = []
    for vulnerability in document.get("vulnerabilities", []):
        cve_id = vulnerability.get("cve")
        if not cve_id:
            continue
        dispositions = _remediation_dispositions(vulnerability)
        for status, product_ids in vulnerability.get("product_status", {}).items():
            for product_id in product_ids:
                helper = products.get(product_id.split(":", 1)[0], products.get(product_id, {}))
                if not in_target_stream(product_id, helper):
                    continue
                status_rows.append((uri, cve_id, product_id, status))
                component, evr = _component_and_evr(product_id, helper)
                if not component:
                    continue
                disposition = ", ".join(sorted(dispositions.get(product_id, set())))
                rpm_rows.append((uri, cve_id, component, evr or "", _stream(product_id, helper) or "", status,
                                 disposition,
                                 document.get("document", {}).get("title", ""), _severity(vulnerability), _cvss(vulnerability)))
    return product_rows, status_rows, rpm_rows


def sync(cache_path, module, workers=8):
    """Synchronize the cache after serializing writers from local processes."""
    with _sync_lock(cache_path):
        return _sync_unlocked(cache_path, module, workers)


def rebuild(cache_path, module=None, workers=8):
    """Discard this derived cache and build it again under the writer lock."""
    with _sync_lock(cache_path):
        _discard_cache_files(cache_path)
        return _sync_unlocked(cache_path, module, workers)


def _sync_unlocked(cache_path, module, workers=8):
    """Fetch only VEX documents changed since this cache was last updated.

    The cache retains every public Red Hat VEX product.  Report evaluation
    selects its applicable product stream at query time, so future product
    support never requires rebuilding the cache.
    """
    connection = _connect(cache_path)
    cached_scope = connection.execute(
        "SELECT value FROM cache_metadata WHERE key = 'scope'"
    ).fetchone()
    cached_feed = connection.execute("SELECT value FROM cache_metadata WHERE key = 'feed_url'").fetchone()
    build_state = connection.execute(
        "SELECT value FROM cache_metadata WHERE key = 'build_state'"
    ).fetchone()
    cached_schema = connection.execute(
        "SELECT value FROM cache_metadata WHERE key = 'schema_version'"
    ).fetchone()
    scope_changed = cached_scope != ("global",) or not cached_feed or cached_feed[0] != VEX_BASE_URL
    if scope_changed:
        # An earlier cache may be limited to one RHEL major or use a different
        # source feed, so it cannot safely answer an all-products query.
        connection.close()
        _discard_cache_files(cache_path)
        connection = _connect(cache_path)
    elif cached_schema != (CACHE_SCHEMA_VERSION,):
        if not _migrate_schema(connection, cached_schema):
            # Unknown historical formats are not safe to migrate.  This path
            # is deliberately limited to obsolete formats; Update never
            # rebuilds a recognized cache just because a new field was added.
            connection.close()
            _discard_cache_files(cache_path)
            connection = _connect(cache_path)
    connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('scope', 'global')")
    connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('feed_url', ?)", (VEX_BASE_URL,))
    connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('schema_version', ?)", (CACHE_SCHEMA_VERSION,))
    # ``changes.csv`` is the small feed index.  It is read on every refresh so
    # document timestamps can be compared locally; individual CSAF documents
    # are requested only when their listed modification time changed.
    changes = list(csv.reader(io.StringIO(_request(VEX_BASE_URL + "changes.csv", "text/csv"))))
    # The feed has published the same CVE paths in both upper- and lower-case
    # variants.  URLs are case-sensitive, while the archive uses lower-case;
    # canonicalize before comparing or fetching so a case-only feed change
    # cannot turn valid documents into thousands of false 404s.
    remote = {_canonical_uri(row[0]): row[1] for row in changes if len(row) >= 2}
    existing = dict(connection.execute("SELECT uri, modified FROM documents"))
    unavailable = dict(connection.execute("SELECT uri, modified FROM unavailable_documents"))
    pending = [
        (uri, modified) for uri, modified in remote.items()
        if existing.get(uri) != modified and unavailable.get(uri) != modified
    ]

    def index(uri, modified, document):
        _, _, rpm_rows = _normalized_rows(uri, document)
        connection.execute("DELETE FROM rpm_status WHERE uri = ?", (uri,))
        connection.execute("DELETE FROM documents WHERE uri = ?", (uri,))
        # Clear a prior false 404 recorded under an upper-case path before
        # indexing the canonical lower-case URL.
        connection.execute("DELETE FROM unavailable_documents WHERE lower(uri) = lower(?)", (uri,))
        connection.execute("INSERT INTO documents(uri, modified) VALUES (?, ?)", (uri, modified))
        connection.executemany("INSERT OR IGNORE INTO rpm_status VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rpm_rows)

    def fetch(item):
        uri, modified = item
        for attempt in range(DOCUMENT_FETCH_ATTEMPTS):
            try:
                return uri, modified, json.loads(_request(VEX_BASE_URL + uri)), None
            except urllib.error.HTTPError as error:
                # ``changes.csv`` can retain entries that are not part of the
                # published feed any longer.  A 404 is therefore a stable
                # feed condition, not a cache-build failure.  Remember it so
                # future refreshes do not request it again.
                if error.code == 404:
                    return uri, modified, None, "HTTP 404"
                if error.code not in {408, 425, 429, 500, 502, 503, 504}:
                    raise
                last_error = error
            except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as error:
                last_error = error
            if attempt == DOCUMENT_FETCH_ATTEMPTS - 1:
                raise last_error
            # Keep the full-cache import moving during a temporary feed or
            # network hiccup.  This is intentionally independent of BOMQ's
            # much smaller two-request service limit.
            time.sleep(min(8, 0.5 * (2 ** attempt)))

    def mark_unavailable(uri, modified, reason):
        connection.execute(
            "INSERT OR REPLACE INTO unavailable_documents(uri, modified, reason) VALUES (?, ?, ?)",
            (uri, modified, reason),
        )

    is_initial_build = build_state == ("building",)
    if (not existing and pending and zstd is not None) or is_initial_build:
        connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('build_state', 'building')")
        _begin_bulk_load(connection)
        indexed = len(existing)
        skipped = 0
        documents = []
        rpm_statuses = []

        def queue_archive_rows(uri, modified, document):
            _, _, rpm_rows = _normalized_rows(uri, document)
            documents.append((uri, modified))
            rpm_statuses.extend(rpm_rows)

        def flush_archive_rows():
            # A process may have committed a batch immediately before an
            # interruption.  On resume, the manifest can legitimately queue
            # that URI again (for example when its timestamp advanced), so
            # replace its document marker and stale normalized rows as one
            # idempotent batch rather than treating it as a fatal duplicate.
            unique_documents = list(dict.fromkeys(documents))
            connection.executemany("DELETE FROM rpm_status WHERE uri = ?",
                                   [(uri,) for uri, _ in unique_documents])
            connection.executemany("DELETE FROM unavailable_documents WHERE uri = ?",
                                   [(uri,) for uri, _ in unique_documents])
            connection.executemany("INSERT OR REPLACE INTO documents(uri, modified) VALUES (?, ?)",
                                   unique_documents)
            connection.executemany("INSERT OR IGNORE INTO rpm_status VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rpm_statuses)
            documents.clear()
            rpm_statuses.clear()

        if not existing:
            print(f"  VEX cache: initializing shared cache from {VEX_ARCHIVE_URL}...", file=sys.stderr, flush=True)
            for uri, modified, document in _archive_documents(remote):
                queue_archive_rows(uri, modified, document)
                indexed += 1
                if indexed % 1000 == 0:
                    flush_archive_rows()
                    connection.commit()
                    print(f"  VEX cache: indexed {indexed}/{len(remote)} archive documents", file=sys.stderr, flush=True)
        else:
            print(f"  VEX cache: resuming incomplete initialization from {indexed} indexed document(s)...",
                  file=sys.stderr, flush=True)
        if documents:
            flush_archive_rows()
        existing = dict(connection.execute("SELECT uri, modified FROM documents"))
        unavailable = dict(connection.execute("SELECT uri, modified FROM unavailable_documents"))
        pending = [
            (uri, modified) for uri, modified in remote.items()
            if existing.get(uri) != modified and unavailable.get(uri) != modified
        ]
        print(f"  VEX cache: archive indexed {indexed} document(s); {len(pending)} archive-missing document(s) remain", file=sys.stderr, flush=True)
        if pending:
            print(f"  VEX cache: bulk-fetching archive-missing documents with {ARCHIVE_CATCHUP_WORKERS} workers...",
                  file=sys.stderr, flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=ARCHIVE_CATCHUP_WORKERS) as executor:
                futures = [executor.submit(fetch, item) for item in pending]
                for number, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    uri, modified, document, unavailable_reason = future.result()
                    if unavailable_reason:
                        mark_unavailable(uri, modified, unavailable_reason)
                        skipped += 1
                    else:
                        queue_archive_rows(uri, modified, document)
                    if number % 1000 == 0:
                        flush_archive_rows()
                        connection.commit()
                        print(f"  VEX cache: indexed {indexed + number}/{len(remote)} documents", file=sys.stderr, flush=True)
        if documents:
            flush_archive_rows()
        _finish_bulk_load(connection)
        if skipped:
            print(f"  VEX cache: skipped {skipped} withdrawn document(s) listed by the feed.",
                  file=sys.stderr, flush=True)
        connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('build_state', 'ready')")
        connection.commit()
        pending = []
    else:
        print(f"  VEX cache: {len(pending)} changed document(s)", file=sys.stderr, flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for number, future in enumerate(concurrent.futures.as_completed([executor.submit(fetch, item) for item in pending]), 1):
            uri, modified, document, unavailable_reason = future.result()
            if unavailable_reason:
                mark_unavailable(uri, modified, unavailable_reason)
            else:
                index(uri, modified, document)
            if number % 100 == 0:
                connection.commit()
                print(f"  VEX cache: indexed {number}/{len(pending)} documents", file=sys.stderr, flush=True)
    connection.execute(
        "INSERT OR REPLACE INTO cache_metadata VALUES ('last_sync_at', ?)",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"),),
    )
    connection.execute("INSERT OR REPLACE INTO cache_metadata VALUES ('build_state', 'ready')")
    connection.commit()
    connection.close()
    return len(pending)


def _stream_from_bomq(stream):
    match = re.search(r"rhel-(\d+)\.(\d+)(?:\.z)?$", stream or "")
    return f"{match.group(1)}.{match.group(2)}" if match else None


def _stream_from_nvr(module, nvr):
    module_match = re.fullmatch(r"rhel-(\d+)", module)
    if not module_match:
        return None
    major = module_match.group(1)
    nvr_match = re.search(r"\.el" + re.escape(major) + r"[_\.](\d+)", nvr or "")
    return f"{major}.{nvr_match.group(1) if nvr_match else '0'}"


def _target_stream(module, installed, bomq_stream, upstream_origins, component,
                   stream_hints=None):
    """Resolve the VEX product stream from image-specific provenance.

    An RPM release such as ``.el10`` is only a major-version marker.  It must
    not override BOMQ evidence that the source build belongs to RHEL 10.2.
    """
    explicit = _stream_from_bomq(bomq_stream)
    if explicit:
        return explicit, None
    inferred = _stream_from_nvr(module, installed)
    # An exact Pyxis image manifest can establish a binary RPM's RHEL minor
    # stream even when the associated source build carries only ``.el<major>``.
    # This is image-manifest evidence, not BOMQ release provenance.
    hints = {
        stream for nvr in (stream_hints or {}).get((component, installed), set())
        if (stream := _stream_from_nvr(module, nvr))
    }
    if hints:
        if inferred and not inferred.endswith(".0"):
            return inferred, None
        if len(hints) == 1:
            return next(iter(hints)), None
        return None, "Pyxis image manifest identifies multiple RHEL streams"
    origin_streams = {
        stream for value in upstream_origins.get((component, installed), set())
        if (stream := _stream_from_bomq(value))
    }
    # A release-qualified RPM is more precise than an image-wide inference.
    if inferred in origin_streams and not inferred.endswith(".0"):
        return inferred, None
    image_stream = _image_stream(upstream_origins)
    if image_stream in origin_streams:
        return image_stream, None
    if inferred in origin_streams:
        return inferred, None
    if len(origin_streams) == 1:
        return next(iter(origin_streams)), None
    if origin_streams:
        return None, "BOMQ provenance identifies multiple upstream streams"
    return inferred, None


def _image_stream(upstream_origins):
    """Infer one image stream from all BOMQ source-build provenance.

    Shared source builds can appear in several downstream streams.  Their
    ``.el<major>`` NVR does not select one; use the dominant stream evidenced
    by the image's other origin builds, but leave a tie unresolved.
    """
    stream_counts = defaultdict(int)
    for streams in upstream_origins.values():
        for value in streams:
            if stream := _stream_from_bomq(value):
                stream_counts[stream] += 1
    if not stream_counts:
        return None
    highest = max(stream_counts.values())
    candidates = [stream for stream, count in stream_counts.items() if count == highest]
    return candidates[0] if len(candidates) == 1 else None


def _fixed_at_or_before(installed_evr, fixed_evr, compare_evr):
    return bool(installed_evr and fixed_evr and compare_evr(installed_evr, fixed_evr) >= 0)


def _rpm_name(nvr):
    name_parts = []
    for index, part in enumerate(nvr.split("-")):
        if index and part and part[0].isdigit():
            break
        name_parts.append(part)
    return "-".join(name_parts)


def findings(cache_path, component_nvrs, module, compare_evr, bomq_stream=None,
             component_origins=None, upstream_origins=None, stream_hints=None):
    """Return ``(unresolved, unknown)`` VEX results for installed source NEVRs.

    Exact product-build states override generic component states.  A fixed
    exact build is interpreted as an EVR threshold within the same stream;
    an image at or beyond it is no longer reported.
    """
    if not Path(cache_path).exists():
        raise RuntimeError(f"VEX cache does not exist: {cache_path}; run again with --sync-vex")
    connection = _connect(cache_path)
    results = []
    unknown = []
    component_origins = component_origins or {}
    upstream_origins = upstream_origins or {}
    stream_hints = stream_hints or {}
    unsafe = {"known_affected", "under_investigation", "first_affected"}
    safe = {"known_not_affected", "fixed", "first_fixed"}
    for component, nvrs in component_nvrs.items():
        # VEX product PURLs identify the delivered binary RPM.  The image
        # report is keyed by source RPM, so search both names.  This covers
        # source/binary renames such as rust-rpm-sequoia -> rpm-sequoia.
        aliases = {component}
        aliases.update(_rpm_name(nvr) for nvr in component_origins.get(component, set()))
        rows = []
        for alias in aliases:
            rows.extend(connection.execute(
                "SELECT cve_id, evr, stream, status, disposition, title, impact, cvss FROM rpm_status WHERE component = ?",
                (alias,),
            ).fetchall())
        for installed in nvrs or {None}:
            evr = installed.rsplit("-", 2)[1:] if installed else []
            installed_evr = "-".join(evr) if len(evr) == 2 else None
            target_stream, stream_error = _target_stream(
                module, installed, bomq_stream, upstream_origins, component, stream_hints
            )
            if not target_stream or not installed_evr:
                unknown.append((component, installed or "(missing NVR)",
                                stream_error or "stream or EVR could not be determined"))
                continue
            major_stream = target_stream.split(".", 1)[0] + ".0"
            # Generic RHEL-major states are encoded as ``major.0`` without an
            # EVR.  A build-specific 10.0 state must not apply to 10.2.
            applicable = [
                row for row in rows
                if row[2] == target_stream or (row[2] == major_stream and row[1] == "")
            ]
            states_by_cve = defaultdict(list)
            for row in applicable:
                states_by_cve[row[0]].append(row)

            # Product status is a property of a CVE/component relationship.
            # Do not let a fixed or not-affected state for one CVE suppress an
            # unrelated affected CVE for the same source RPM.
            has_effective_state = False
            for cve_id, cve_rows in states_by_cve.items():
                exact = [row for row in cve_rows if row[1] and row[2] == target_stream]
                generic = [row for row in cve_rows if not row[1]]
                exact_safe = [
                    row for row in exact
                    if (row[3] in {"fixed", "first_fixed"}
                        and _fixed_at_or_before(installed_evr, row[1], compare_evr))
                    or (row[3] == "known_not_affected" and row[1] == installed_evr)
                ]
                if exact_safe:
                    has_effective_state = True
                    continue

                exact_unsafe = [
                    row for row in exact if row[3] in unsafe and row[1] == installed_evr
                ]
                candidates = exact_unsafe
                if not candidates:
                    if any(row[3] in safe for row in generic):
                        has_effective_state = True
                        continue
                    candidates = [row for row in generic if row[3] in unsafe]
                if not candidates:
                    continue
                has_effective_state = True
                seen_candidates = set()
                for _, _, _, status, disposition, title, impact, cvss in candidates:
                    candidate_key = (status, disposition, title, impact, cvss)
                    if candidate_key in seen_candidates:
                        continue
                    seen_candidates.add(candidate_key)
                    results.append({"cve_id": cve_id, "impact": impact, "cvss": cvss, "title": title,
                                    "component": component, "affectedness": "AFFECTED", "resolution": status,
                                    "disposition": disposition,
                                    "workflow_state": "PUBLIC VEX",
                                    "origin_component": component,
                                    "origin_nvrs": [installed],
                                    "image_components": sorted(component_origins.get(component, {component})),
                                    "upstream_streams": sorted(upstream_origins.get((component, installed), set()))})
            if not has_effective_state:
                unknown.append((component, installed, f"no applicable VEX state for {target_stream}"))
    return results, unknown


def fixed_component_statuses(cache_path, component_nvrs, cve_components, module, compare_evr,
                             component_origins=None, upstream_origins=None):
    """Return build-specific fixed/not-affected VEX states for OSIDB candidates.

    The OSIDB report path uses this as a one-way reconciliation: VEX can prove
    that a matching origin build is fixed even while its tracker affect remains
    open or delegated.  It never treats an absent VEX record as safe.
    """
    if not Path(cache_path).exists():
        return {}
    connection = _connect(cache_path)
    statuses = {}
    component_origins = component_origins or {}
    upstream_origins = upstream_origins or {}
    requested = set(cve_components)
    try:
        for component, nvrs in component_nvrs.items():
            requested_cves = {cve_id for cve_id, name in requested if name == component}
            if not requested_cves:
                continue
            aliases = {component}
            aliases.update(_rpm_name(nvr) for nvr in component_origins.get(component, set()))
            rows = []
            for alias in aliases:
                placeholders = ",".join("?" for _ in requested_cves)
                rows.extend(connection.execute(
                    "SELECT cve_id, evr, stream, status FROM rpm_status "
                    f"WHERE component = ? AND cve_id IN ({placeholders})",
                    (alias, *sorted(requested_cves)),
                ).fetchall())
            for installed in nvrs:
                evr_parts = installed.rsplit("-", 2)
                if len(evr_parts) != 3:
                    continue
                installed_evr = "-".join(evr_parts[1:])
                target_stream, _ = _target_stream(
                    module, installed, None, upstream_origins, component
                )
                if not target_stream:
                    continue
                major_stream = target_stream.split(".", 1)[0] + ".0"
                for cve_id in requested_cves:
                    applicable = [
                        row for row in rows
                        if row[0] == cve_id
                        and (row[2] == target_stream or (row[2] == major_stream and row[1] == ""))
                    ]
                    if any(
                        row[3] in {"fixed", "first_fixed"}
                        and _fixed_at_or_before(installed_evr, row[1], compare_evr)
                        for row in applicable if row[1]
                    ):
                        statuses[(cve_id, component)] = "fixed"
                    elif any(
                        row[3] == "known_not_affected" and row[1] == installed_evr
                        for row in applicable
                    ):
                        statuses[(cve_id, component)] = "not a bug"
    finally:
        connection.close()
    return statuses
