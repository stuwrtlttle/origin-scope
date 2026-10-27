#!/usr/bin/env python3
"""
Query OSIDB for unresolved CVEs affecting packages from an SBOM or component list.

Supported input formats (auto-detected):
  - Syft JSON (.json with $.artifacts[])
  - SPDX 2.3 JSON with RPM purls (.spdx.json or .json)
  - SPDX 2.3 container image SBOM (OCI-only; resolves RPMs via Pyxis)
  - CycloneDX JSON (.cdx.json or $.bomFormat == "CycloneDX")
  - Plain text (one NVRA per line, e.g. bash-4.4.20-6.el8_10.x86_64)

Usage:
  python3 scripts/cve_report.py sbom.spdx.json
  python3 scripts/cve_report.py --module rhel-9 components.txt
  python3 scripts/cve_report.py --env uat sbom.json
  cat components.txt | python3 scripts/cve_report.py -
"""

import argparse
import concurrent.futures
import json
import random
import re
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path

import vex_cache
import scanner_csv

ENVS = {
    "prod": "https://osidb.prodsec.redhat.com",
    "uat": "https://osidb-uat.prodsec.redhat.com",
}
PYXIS_URL = "https://catalog.redhat.com/api/containers/v1"
SECURITY_DATA_URL = "https://access.redhat.com/hydra/rest/securitydata/cve"
BOMQ_URL = "https://bomq.prodsec.redhat.com/api/v0"
BOMQ_WORKERS = 2
VEX_EXPORT_ENGINE = "cve-report"
VEX_EXPORT_VERSION = "1.0"

# A delegated affect remains unresolved for the shipped component and must be
# reported alongside NEW, FIX, and DEFER affects.
OPEN_RESOLUTIONS = {"", "FIX", "DEFER", "DELEGATED"}


TERMINAL_TRACKER_RESOLUTIONS = {"Done", "Done-Errata", "Not a Bug", "Obsolete"}


def is_shipped_by_tracker(affect):
    """Return True when every tracker linked to this affect shipped an erratum.

    Affect-level resolution is a workflow routing value (for example,
    ``DELEGATED``), not a delivery-state signal.  Only consider trackers that
    explicitly reference this affect: the API can include other trackers for
    the same flaw.
    """
    affect_uuid = affect.get("uuid")
    trackers = [
        tracker for tracker in affect.get("trackers", [])
        if affect_uuid in tracker.get("affects", [])
    ]
    return bool(trackers) and all(
        tracker.get("status") == "Closed"
        and tracker.get("resolution") in TERMINAL_TRACKER_RESOLUTIONS
        for tracker in trackers
    )


def origin_affect_status(affect):
    """Map a terminal OSIDB origin affect state to a user-facing status.

    ``DELEGATED`` still means the component is affected; it merely assigns
    remediation to the owning product team.  A delegated affect marked Done
    is fixed.  A delegated affect marked Not a Bug is distinct from fixed.
    ``None`` leaves the fixed-build comparison to determine the status.
    """
    affectedness = (affect.get("affectedness") or "").strip().upper()
    resolution = (affect.get("resolution") or "").strip().lower().replace("_", "-")
    delegated = affectedness == "DELEGATED" or resolution == "delegated"
    if not delegated:
        return None
    tracker_resolutions = {
        (tracker.get("resolution") or "").strip().lower().replace("_", "-")
        for tracker in affect.get("trackers", [])
        if affect.get("uuid") in tracker.get("affects", [])
    }
    terminal_resolutions = tracker_resolutions | {resolution}
    if "not a bug" in terminal_resolutions:
        return "not a bug"
    if terminal_resolutions & {"done", "done-errata"}:
        return "fixed"
    return None


def cve_remediation_status(component_statuses):
    """Return the conservative image-level status from origin components."""
    statuses = set(component_statuses)
    if "unfixed" in statuses:
        return "unfixed"
    if "fixed" in statuses:
        return "fixed"
    if statuses == {"not a bug"}:
        return "not a bug"
    return None

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

EL_RE = re.compile(r"\.el(\d+)")
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def canonical_cve_id(value):
    """Return a canonical public CVE identifier, never an OSIDB UUID."""
    value = (value or "").strip()
    return value.upper() if CVE_ID_RE.fullmatch(value) else None


def load_cve_filter(path):
    """Load a newline-delimited allowlist of public CVE IDs."""
    if not path:
        return None
    cve_ids = {
        cve_id for line in Path(path).read_text(encoding="utf-8").splitlines()
        if (cve_id := canonical_cve_id(line))
    }
    if not cve_ids:
        raise ValueError("CVE filter contains no public CVE IDs")
    return cve_ids


def load_component_filter(path):
    """Load scanner package names used to limit origin-component lookups."""
    if not path:
        return None
    components = {line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()}
    if not components:
        raise ValueError("component filter contains no package names")
    return components


def select_scanner_components(components, component_origins, requested_components):
    """Map scanner package names to their source RPMs in the image inventory."""
    if requested_components is None:
        return set(components)
    selected = set()
    for component in components:
        image_names = {
            parse_rpm_name(binary_nvr) or binary_nvr
            for binary_nvr in component_origins.get(component, set())
        }
        if component in requested_components or image_names & requested_components:
            selected.add(component)
    return selected


# ---------------------------------------------------------------------------
# HTTP helpers (reused from previous script)
# ---------------------------------------------------------------------------

def fetch_json(url, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cve-report/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=180) as resp:
                return json.load(resp)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                print(f"  Retry {attempt + 1} for {url[:100]}...", file=sys.stderr, flush=True)
            else:
                raise


def fetch_bomq_json(url, retries=5):
    """Fetch BOMQ conservatively; its proxy can reset bursty connections."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cve-report/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=180) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code not in {408, 425, 429}:
                raise
            error = exc
        except Exception as exc:
            error = exc
        if attempt == retries - 1:
            raise error
        delay = min(30, 2 ** attempt) + random.uniform(0, 0.5)
        print(f"  BOMQ retry {attempt + 1}/{retries - 1} in {delay:.1f}s for {url[:100]}...",
              file=sys.stderr, flush=True)
        time.sleep(delay)


def fetch_security_data(cve_id, retries=3):
    """Fetch public Red Hat CVE data, returning None when it is not public."""
    url = f"{SECURITY_DATA_URL}/{urllib.parse.quote(cve_id)}.json"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cve-report/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=180) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if attempt == retries - 1:
                raise
        except Exception:
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)


def paginate(url_template, page_size=200):
    offset = 0
    while True:
        data = fetch_json(url_template.format(limit=page_size, offset=offset))
        yield from data["results"]
        offset += page_size
        if offset >= data["count"]:
            break


# ---------------------------------------------------------------------------
# RPM NVR comparison and source-build provenance
# ---------------------------------------------------------------------------

def split_rpm_nvr(nvr):
    """Split ``name-epoch:version-release`` or ``name-version-release``."""
    value = extract_source_nvr_from_srpm(nvr.strip())
    parts = value.rsplit("-", 2)
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        return None
    return parts[0], f"{parts[1]}-{parts[2]}"


def split_evr(evr):
    epoch = 0
    version_release = evr
    if ":" in evr:
        candidate_epoch, version_release = evr.split(":", 1)
        if candidate_epoch.isdigit():
            epoch = int(candidate_epoch)
        else:
            version_release = evr
    if "-" not in version_release:
        return epoch, version_release, ""
    version, release = version_release.rsplit("-", 1)
    return epoch, version, release


def rpmvercmp(left, right):
    """Compare RPM version segments without requiring the rpm Python module."""
    if left == right:
        return 0
    i = j = 0
    left_len, right_len = len(left), len(right)
    while i < left_len or j < right_len:
        if i < left_len and left[i] == "~":
            if j >= right_len or right[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if j < right_len and right[j] == "~":
            return 1
        if i < left_len and left[i] == "^":
            if j >= right_len:
                return 1
            if right[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if j < right_len and right[j] == "^":
            if i >= left_len:
                return -1
            return 1

        while i < left_len and not left[i].isalnum() and left[i] not in "~^":
            i += 1
        while j < right_len and not right[j].isalnum() and right[j] not in "~^":
            j += 1
        if i >= left_len or j >= right_len:
            break

        left_numeric = left[i].isdigit()
        right_numeric = right[j].isdigit()
        if left_numeric != right_numeric:
            return 1 if left_numeric else -1

        i_end = i
        while i_end < left_len and left[i_end].isalnum() and left[i_end].isdigit() == left_numeric:
            i_end += 1
        j_end = j
        while j_end < right_len and right[j_end].isalnum() and right[j_end].isdigit() == right_numeric:
            j_end += 1

        left_segment = left[i:i_end]
        right_segment = right[j:j_end]
        if left_numeric:
            left_segment = left_segment.lstrip("0") or "0"
            right_segment = right_segment.lstrip("0") or "0"
            if len(left_segment) != len(right_segment):
                return 1 if len(left_segment) > len(right_segment) else -1
        if left_segment != right_segment:
            return 1 if left_segment > right_segment else -1
        i, j = i_end, j_end

    if i < left_len:
        return 1
    if j < right_len:
        return -1
    return 0


def compare_evr(left, right):
    """Compare two RPM EVRs, returning -1, 0, or 1."""
    left_epoch, left_version, left_release = split_evr(left)
    right_epoch, right_version, right_release = split_evr(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    version_cmp = rpmvercmp(left_version, right_version)
    return version_cmp if version_cmp else rpmvercmp(left_release, right_release)


def rhel_minor_from_nvr(nvr):
    """Return the RHEL minor encoded in an RPM NVR (``el10_2`` -> 2)."""
    match = re.search(r"\.el\d+[_\.](\d+)", nvr)
    return int(match.group(1)) if match else 0


def rhel_minor_from_cpe(cpe):
    match = re.search(r"enterprise_linux:(\d+)(?:\.(\d+))?", cpe or "")
    if not match:
        return None
    return int(match.group(2) or 0)


def rhel_major_from_module(module):
    """Return the RHEL major encoded by an OSIDB product-stream module."""
    match = re.fullmatch(r"rhel-(\d+)", module or "")
    return int(match.group(1)) if match else None


def rhel_release_entries(security_data, module, component, installed_nvr):
    """Return fixed NVRs applicable to an installed RHEL source build.

    The product release must match the module inferred from the SBOM provenance.
    A source NVR such as ``foo-1-1.el9`` does not encode a minor release, so it
    is intentionally eligible for all RHEL 9 fixed-build records.
    """
    major = rhel_major_from_module(module)
    if major is None:
        return []
    installed_minor = rhel_minor_from_nvr(installed_nvr)
    candidates = []
    for release in security_data.get("affected_release", []):
        if not (release.get("product_name") == f"Red Hat Enterprise Linux {major}"
                or release.get("cpe", "").startswith(
                    f"cpe:/o:redhat:enterprise_linux:{major}"
                )):
            continue
        parsed = split_rpm_nvr(release.get("package", ""))
        if not parsed or parsed[0] != component:
            continue
        release_minor = rhel_minor_from_cpe(release.get("cpe", ""))
        if (installed_minor and release_minor is not None
                and release_minor > installed_minor):
            continue
        candidates.append((parsed[1], release.get("advisory", "")))
    return candidates


def rhel10_release_entries(security_data, component, installed_nvr):
    """Backward-compatible RHEL 10 wrapper for callers outside this module."""
    return rhel_release_entries(security_data, "rhel-10", component, installed_nvr)


def component_status_from_security_data(security_data, module, component, installed_nvrs):
    """Return ``(fixed, reason, advisories)`` for installed source NVR(s).

    A component is fixed only when every installed origin build is at or
    beyond the applicable public fixed build.  Tracker routing state is not
    used: an older image remains unfixed even when an OSIDB tracker is done.
    """
    major = rhel_major_from_module(module)
    if major is None:
        return False, "the RHEL major could not be determined", set()
    if not isinstance(security_data, dict):
        return False, "no public Red Hat fixed-build data", set()

    for package_state in security_data.get("package_state", []):
        if (package_state.get("product_name") == f"Red Hat Enterprise Linux {major}"
                and package_state.get("package_name") == component
                and package_state.get("fix_state") == "Not affected"):
            return True, "Red Hat marks the component not affected", set()

    matched_any_release = False
    advisories = set()
    for installed_nvr in installed_nvrs:
        parsed = split_rpm_nvr(installed_nvr)
        if not parsed:
            return False, "installed origin NVR could not be parsed", set()
        _, installed_evr = parsed
        candidates = rhel_release_entries(security_data, module, component, installed_nvr)
        if not candidates:
            continue
        matched_any_release = True
        fixed_evr, advisory = max(candidates, key=cmp_to_key(lambda left, right: compare_evr(left[0], right[0])))
        advisories.add(advisory)
        if compare_evr(installed_evr, fixed_evr) < 0:
            return False, f"installed {installed_evr} precedes fixed {fixed_evr}", set()

    if matched_any_release:
        advisory_text = ", ".join(sorted(a for a in advisories if a))
        return (True,
                f"installed origin build meets fixed NVR{f' ({advisory_text})' if advisory_text else ''}",
                {advisory for advisory in advisories if advisory})
    return False, f"no matching RHEL {major} fixed NVR", set()


def bomq_has_source_build(stream, component, nvr):
    """Whether BOMQ records the exact source build in the expected stream."""
    parsed = split_rpm_nvr(nvr)
    if not parsed:
        return False
    name, evr = parsed
    no_epoch_evr = evr.split(":", 1)[-1]
    # BOMQ's exact purl matcher includes qualifiers.  We are validating the
    # source package that supplies the image RPMs, not an arbitrary binary.
    purl = f"pkg:rpm/redhat/{name}@{no_epoch_evr}?arch=src"
    url = f"{BOMQ_URL}/streams/{urllib.parse.quote(stream, safe='')}/components?" + urllib.parse.urlencode({
        "purl": purl,
        "strict": "true",
        "include_types": "rpm",
    })
    data = fetch_bomq_json(url)
    return any(
        item.get("name") == name and item.get("version") == no_epoch_evr
        for item in data.get("data", [])
    )


def bomq_origin_streams(module, component, nvr):
    """Return RHEL streams that publish this exact source RPM in BOMQ."""
    parsed = split_rpm_nvr(nvr)
    if not parsed:
        return set()
    name, evr = parsed
    no_epoch_evr = evr.split(":", 1)[-1]
    purl = f"pkg:rpm/redhat/{name}@{no_epoch_evr}?arch=src"
    minor = rhel_minor_from_nvr(nvr or "")
    stream_pattern = f"{module}.{minor}*" if minor else f"{module}*"
    url = f"{BOMQ_URL}/search/components?" + urllib.parse.urlencode({
        "name": name,
        "strict": "true",
        "include_types": "rpm",
        "include_streams": stream_pattern,
    })
    data = fetch_bomq_json(url)
    return {
        item["stream_name"]
        for item in data.get("data", [])
        if item.get("build_type") == "rpm" and item.get("purl") == purl
    }


def bomq_cache_key(module, component, nvr):
    return f"{module}\x1f{component}\x1f{nvr}"


def load_bomq_cache(path):
    """Return cached immutable source-build stream mappings, ignoring bad cache data."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = payload.get("entries", {})
        return entries if isinstance(entries, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_bomq_cache(path, entries):
    """Persist completed BOMQ origin lookups atomically for later analyses."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": "cve-report.bomq-cache/v1", "entries": entries}
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(destination)


def cached_bomq_origin_streams(entries, module, component, nvr):
    entry = entries.get(bomq_cache_key(module, component, nvr))
    if not isinstance(entry, dict) or not isinstance(entry.get("streams"), list):
        return None
    return set(stream for stream in entry["streams"] if isinstance(stream, str))


def cache_bomq_origin_streams(entries, module, component, nvr, streams):
    entries[bomq_cache_key(module, component, nvr)] = {
        "streams": sorted(streams),
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def resolve_bomq_origin_streams(module, component_nvrs, cache_path):
    """Resolve and cache the RHEL stream for every installed source build.

    This supports both public-VEX and OSIDB reporting.  Stream discovery is
    provenance, not vulnerability disposition, so it must not depend on the
    source selected for vulnerability status.
    """
    source_builds = sorted({
        (component, nvr)
        for component, nvrs in component_nvrs.items()
        for nvr in nvrs
    })
    if not source_builds:
        print("  BOMQ origin lookup skipped: input has no RPM NVRs", file=sys.stderr, flush=True)
        return {}
    entries = load_bomq_cache(cache_path)
    origins = {}
    pending = []
    for component, nvr in source_builds:
        cached = cached_bomq_origin_streams(entries, module, component, nvr)
        if cached is None:
            pending.append((component, nvr))
        else:
            origins[(component, nvr)] = cached
    print(f"\nResolving BOMQ upstream streams for {len(source_builds)} source build(s) "
          f"({len(origins)} cached; {len(pending)} request(s), max {BOMQ_WORKERS} concurrent)...",
          file=sys.stderr, flush=True)
    cache_changed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(BOMQ_WORKERS, max(1, len(pending)))) as executor:
        futures = {
            executor.submit(bomq_origin_streams, module, component, nvr): (component, nvr)
            for component, nvr in pending
        }
        for future in concurrent.futures.as_completed(futures):
            component, nvr = futures[future]
            try:
                streams = future.result()
            except Exception as exc:
                streams = set()
                print(f"  BOMQ origin lookup failed for {nvr}: {exc}", file=sys.stderr, flush=True)
            origins[(component, nvr)] = streams
            cache_bomq_origin_streams(entries, module, component, nvr, streams)
            cache_changed = True
    if cache_changed:
        save_bomq_cache(cache_path, entries)
    return origins


# ---------------------------------------------------------------------------
# SBOM parsing — each returns (set[str] components, str|None rhel_version)
# ---------------------------------------------------------------------------

def extract_source_name_from_srpm(srpm_filename):
    """Parse source RPM name from a filename like 'glibc-2.28-251.el8.src.rpm'."""
    name = srpm_filename
    if name.endswith(".src.rpm"):
        name = name[:-8]
    elif name.endswith(".rpm"):
        name = name[:-4]
    parts = name.rsplit("-", 2)
    if len(parts) >= 3:
        return parts[0]
    return name


def extract_source_nvr_from_srpm(srpm_filename):
    """Return an SRPM NVR without the .src.rpm suffix."""
    if srpm_filename.endswith(".src.rpm"):
        return srpm_filename[:-8]
    if srpm_filename.endswith(".src"):
        return srpm_filename[:-4]
    if srpm_filename.endswith(".rpm"):
        return srpm_filename[:-4]
    return srpm_filename


def format_rpm_nvr(name, evr, epoch="0"):
    """Format an RPM NVR, retaining a non-zero epoch when one is available."""
    if epoch and epoch not in {"0", "(none)"}:
        return f"{name}-{epoch}:{evr}"
    return f"{name}-{evr}" if evr else name


def parse_rpm_name(nvra):
    """Extract binary package name from an NVRA string like 'bash-4.4.20-6.el8_10.x86_64'."""
    stripped = nvra.rsplit(".", 1)[0]
    segments = stripped.split("-")
    name_parts = []
    for i, seg in enumerate(segments):
        if i > 0 and seg and seg[0].isdigit():
            break
        name_parts.append(seg)
    return "-".join(name_parts)


def detect_el_version(text):
    """Extract RHEL major version from a string containing '.elN'."""
    m = EL_RE.search(text)
    return int(m.group(1)) if m else None


def parse_syft(data, direct_components=False):
    """Parse Syft JSON format.

    ``direct_components`` retains the RPM component name reported by the
    SBOM.  The default preserves OriginScope's source-RPM grouping.
    """
    components = set()
    el_versions = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)

    for artifact in data.get("artifacts", []):
        if artifact.get("type") != "rpm":
            continue
        meta = artifact.get("metadata", {})
        binary = artifact["name"]
        binary_nvr = format_rpm_nvr(binary, artifact.get("version", ""))
        srpm = meta.get("sourceRpm", "")
        if direct_components:
            component = binary
            components.add(component)
            component_nvrs[component].add(binary_nvr)
            component_origins[component].add(binary_nvr)
        elif srpm:
            component = extract_source_name_from_srpm(srpm)
            components.add(component)
            component_nvrs[component].add(extract_source_nvr_from_srpm(srpm))
            component_origins[component].add(binary_nvr)
        else:
            component = binary
            components.add(component)
            component_origins[component].add(binary_nvr)
            version = artifact.get("version", "")
            if version:
                component_nvrs[component].add(f"{component}-{version}")

        release = meta.get("release", "") or artifact.get("version", "")
        v = detect_el_version(release)
        if v:
            el_versions.add(v)

    distro_ver = data.get("distro", {}).get("versionID", "")
    if distro_ver:
        major = distro_ver.split(".")[0]
        if major.isdigit():
            el_versions.add(int(major))

    rhel = f"rhel-{min(el_versions)}" if el_versions else None
    return components, rhel, component_nvrs, component_origins


def parse_spdx(data, direct_components=False):
    """Parse SPDX 2.3 JSON — either direct or wrapped in in-toto attestation."""
    if "predicate" in data:
        spdx = data["predicate"]
    else:
        spdx = data

    packages = spdx.get("packages", [])

    rpm_components = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)
    oci_digests = []
    el_versions = set()
    oci_tags = []

    for pkg in packages:
        for ref in pkg.get("externalRefs", []):
            loc = ref.get("referenceLocator", "")
            if "pkg:rpm/" in loc:
                parsed = urllib.parse.urlparse(loc)
                path = parsed.path
                name_ver = path.rsplit("/", 1)[-1]
                name, _, version = name_ver.partition("@")
                rpm_components.add(name)
                component_origins[name].add(format_rpm_nvr(name, version))
                if version:
                    component_nvrs[name].add(f"{name}-{version}")
                v = detect_el_version(loc)
                if v:
                    el_versions.add(v)
            elif "pkg:oci/" in loc:
                parsed = urllib.parse.urlparse(loc)
                qs = urllib.parse.parse_qs(parsed.query)
                fragment = parsed.path
                if "@sha256:" in fragment:
                    digest = "sha256:" + fragment.split("@sha256:", 1)[1]
                    oci_digests.append(digest)
                for tag in qs.get("tag", []):
                    oci_tags.append(tag)

    if rpm_components:
        rhel = f"rhel-{min(el_versions)}" if el_versions else None
        return rpm_components, rhel, component_nvrs, component_origins

    # Container image SBOM — no RPMs, use Pyxis to resolve
    if oci_digests:
        print("  SPDX contains OCI images but no RPMs, resolving via Pyxis...", file=sys.stderr, flush=True)
        arch_digests = [d for d in oci_digests if d != oci_digests[0]] if len(oci_digests) > 1 else oci_digests
        digest = arch_digests[0] if arch_digests else oci_digests[0]
        if direct_components:
            components, component_nvrs, component_origins = get_rpms_from_pyxis(
                digest, direct_components=True
            )
        else:
            components, component_nvrs, component_origins = get_rpms_from_pyxis(digest)
        for tag in oci_tags:
            major = tag.split(".")[0]
            if major.isdigit():
                el_versions.add(int(major))
                break
        rhel = f"rhel-{min(el_versions)}" if el_versions else None
        return set(components), rhel, component_nvrs, component_origins

    return set(), None, component_nvrs, component_origins


def parse_cyclonedx(data, direct_components=False):
    """Parse CycloneDX JSON format."""
    components_out = set()
    el_versions = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)

    for comp in data.get("components", []):
        purl = comp.get("purl", "")
        name = comp.get("name", "")
        version = comp.get("version", "")
        properties = {
            item.get("name"): item.get("value")
            for item in comp.get("properties", [])
            if isinstance(item, dict) and item.get("name") and item.get("value")
        }

        if purl.startswith("pkg:rpm/"):
            parsed = urllib.parse.urlparse(purl)
            name_ver = parsed.path.rsplit("/", 1)[-1]
            name, _, version = name_ver.partition("@")
            binary_nvr = format_rpm_nvr(name, version)
            source_name = properties.get("redhat:catalog-source-name", "")
            source_nvr = properties.get("redhat:catalog-source-nvr", "")
            if source_name and source_nvr and not direct_components:
                components_out.add(source_name)
                component_origins[source_name].add(binary_nvr)
                component_nvrs[source_name].add(source_nvr)
            else:
                components_out.add(name)
                component_origins[name].add(binary_nvr)
                if version:
                    component_nvrs[name].add(f"{name}-{version}")
            v = detect_el_version(source_nvr or purl)
            if v:
                el_versions.add(v)
        elif name and version and comp.get("type") == "operating-system":
            # Handle CycloneDX without purl, extract from name/version
            components_out.add(name)
            component_origins[name].add(format_rpm_nvr(name, version))
            component_nvrs[name].add(f"{name}-{version}")
            v = detect_el_version(version)
            if v:
                el_versions.add(v)

    rhel = f"rhel-{min(el_versions)}" if el_versions else None
    return components_out, rhel, component_nvrs, component_origins


def parse_component_list(lines):
    """Parse plain text: one NVRA or component name per line."""
    components = set()
    el_versions = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        nvr = extract_source_nvr_from_srpm(line)
        parsed_nvr = split_rpm_nvr(nvr)
        if parsed_nvr:
            name = parsed_nvr[0]
            component_nvrs[name].add(nvr)
        elif "-" in line and any(c.isdigit() for c in line):
            name = parse_rpm_name(line)
        else:
            name = line
        components.add(name)
        component_origins[name].add(nvr if parsed_nvr else name)
        v = detect_el_version(line)
        if v:
            el_versions.add(v)

    rhel = f"rhel-{min(el_versions)}" if el_versions else None
    return components, rhel, component_nvrs, component_origins


def parse_rpm_manifest(lines, direct_components=False):
    """Parse ``rpm -qa`` TSV rows, including an optional epoch column.

    Accepted layouts are ``name|version-release|arch|sourcerpm`` and
    ``name|epoch|version-release|arch|sourcerpm``.  The latter is required
    for correct NEVR comparison (for example, OpenSSL in RHEL 10).
    """
    components = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)
    el_versions = set()

    for line in lines:
        fields = line.strip().split("|")
        if len(fields) == 4:
            binary, binary_evr, _, srpm = fields
            epoch = "0"
        elif len(fields) == 5:
            binary, epoch, binary_evr, _, srpm = fields
        else:
            continue
        if not srpm or srpm == "(none)":
            continue
        nvr = extract_source_nvr_from_srpm(srpm)
        parsed_nvr = split_rpm_nvr(nvr)
        if not parsed_nvr:
            continue
        component, evr = parsed_nvr
        if direct_components:
            component = binary
            nvr = format_rpm_nvr(binary, binary_evr, epoch)
        elif epoch and epoch not in {"0", "(none)"}:
            nvr = f"{component}-{epoch}:{evr}"
        components.add(component)
        component_nvrs[component].add(nvr)
        component_origins[component].add(format_rpm_nvr(binary, binary_evr, epoch))
        version = detect_el_version(nvr)
        if version:
            el_versions.add(version)

    rhel = f"rhel-{min(el_versions)}" if el_versions else None
    return components, rhel, component_nvrs, component_origins


def get_rpms_from_pyxis(image_digest, direct_components=False):
    """Resolve RPM source component names and NVRs from a container image digest."""
    url = f"{PYXIS_URL}/images?filter=image_id=={image_digest}&include=data._id"
    data = fetch_json(url)
    if not data["data"]:
        print(f"  ERROR: Image not found in Pyxis for digest {image_digest}", file=sys.stderr)
        return set(), defaultdict(set), defaultdict(set)
    image_id = data["data"][0]["_id"]
    rpm_data = fetch_json(f"{PYXIS_URL}/images/id/{image_id}/rpm-manifest")
    srpm_names = set()
    component_nvrs = defaultdict(set)
    component_origins = defaultdict(set)
    for rpm in rpm_data.get("rpms", []):
        srpm = rpm.get("srpm_nevra") or rpm.get("srpm_name", "")
        if direct_components:
            binary = rpm.get("name", "")
            binary_nvra = rpm.get("nvra", "")
            binary_nvr = binary_nvra.rsplit(".", 1)[0] if binary_nvra else format_rpm_nvr(
                binary, rpm.get("version", "")
            )
            if binary:
                srpm_names.add(binary)
                component_nvrs[binary].add(binary_nvr)
                component_origins[binary].add(binary_nvr)
        elif srpm:
            name = extract_source_name_from_srpm(srpm)
            srpm_names.add(name)
            component_nvrs[name].add(extract_source_nvr_from_srpm(srpm))
            binary = rpm.get("name", name)
            binary_nvra = rpm.get("nvra", "")
            binary_nvr = binary_nvra.rsplit(".", 1)[0] if binary_nvra else format_rpm_nvr(binary, rpm.get("version", ""))
            component_origins[name].add(binary_nvr)
    return srpm_names, component_nvrs, component_origins


def _canonical_binary_nvr(nvr):
    """Normalize a binary NVR for comparing SBOM and Pyxis manifest forms.

    Catalog NVRA values omit the zero epoch while CycloneDX RPM PURLs often
    retain it.  Zero is equivalent in this comparison; a non-zero epoch is
    retained so a differing build cannot be mapped by mistake.
    """
    parsed = split_rpm_nvr(nvr)
    if not parsed:
        return nvr
    name, evr = parsed
    return f"{name}-{evr.removeprefix('0:')}"


def map_vex_components_to_pyxis_sources(image_reference, architecture, component_nvrs):
    """Map direct SBOM RPM identities to source RPMs from one exact image.

    The caller supplies direct ``binary-name -> binary-NVR`` inventory from
    an SBOM.  A mapping is accepted only for an exact binary name/NVR match in
    the Catalog RPM manifest.  Missing or ambiguous entries deliberately
    remain direct SBOM identities; this is not a BOMQ-origin fallback.
    """
    subject = scanner_csv.resolve_redhat_image(image_reference, architecture)
    manifest = scanner_csv.fetch_rpm_manifest(subject)
    manifest_by_binary = defaultdict(list)
    for rpm in manifest:
        name = rpm.get("name", "")
        nvra = rpm.get("nvra", "")
        nvr = nvra.rsplit(".", 1)[0] if "." in nvra else ""
        if name and nvr:
            manifest_by_binary[(name, _canonical_binary_nvr(nvr))].append(rpm)

    components = set()
    mapped_nvrs = defaultdict(set)
    component_origins = defaultdict(set)
    stream_hints = defaultdict(set)
    matched = 0
    unmatched = 0
    for binary_name, binary_nvrs in component_nvrs.items():
        for binary_nvr in binary_nvrs:
            candidates = manifest_by_binary.get(
                (binary_name, _canonical_binary_nvr(binary_nvr)), []
            )
            source_candidates = {
                (
                    rpm.get("srpm_name") or extract_source_name_from_srpm(rpm.get("srpm_nevra", "")),
                    extract_source_nvr_from_srpm(rpm.get("srpm_nevra", "")),
                )
                for rpm in candidates
                if rpm.get("srpm_nevra")
            }
            if len(source_candidates) == 1:
                source_name, source_nvr = next(iter(source_candidates))
                if source_name and source_nvr:
                    components.add(source_name)
                    mapped_nvrs[source_name].add(source_nvr)
                    component_origins[source_name].add(binary_nvr)
                    stream_hints[(source_name, source_nvr)].add(binary_nvr)
                    matched += 1
                    continue

            # The SBOM is still authoritative for scope.  Do not discard a
            # package merely because it is absent from the selected manifest.
            components.add(binary_name)
            mapped_nvrs[binary_name].add(binary_nvr)
            component_origins[binary_name].add(binary_nvr)
            stream_hints[(binary_name, binary_nvr)].add(binary_nvr)
            unmatched += 1
    return (components, mapped_nvrs, component_origins, stream_hints,
            subject, matched, unmatched)


def parse_in_toto_provenance(data, direct_components=False):
    """Resolve the RPM inventory referenced by a Konflux in-toto statement."""
    digests = [
        f"sha256:{subject['digest']['sha256']}"
        for subject in data.get("subject", [])
        if subject.get("digest", {}).get("sha256")
    ]
    if not digests:
        return set(), None, defaultdict(set), defaultdict(set)
    print("  Resolving RPMs from the provenance image digest via Pyxis...", file=sys.stderr, flush=True)
    if direct_components:
        components, component_nvrs, component_origins = get_rpms_from_pyxis(
            digests[0], direct_components=True
        )
    else:
        components, component_nvrs, component_origins = get_rpms_from_pyxis(digests[0])
    annotations = (
        data.get("predicate", {}).get("buildConfig", {}).get("tasks", [{}])[0]
        .get("invocation", {}).get("environment", {}).get("annotations", {})
    )
    target_branch = annotations.get("build.appstudio.redhat.com/target_branch", "")
    major_match = re.fullmatch(r"rhel-(\d+)(?:\.\d+)?", target_branch)
    rhel = f"rhel-{major_match.group(1)}" if major_match else None
    return components, rhel, component_nvrs, component_origins


def parse_input(path, direct_components=False):
    """Auto-detect format and parse input, returning (components, rhel_version)."""
    if path == "-":
        lines = sys.stdin.read().splitlines()
        if lines and all(len(line.split("|")) in {4, 5} for line in lines if line.strip()):
            return parse_rpm_manifest(lines, direct_components=direct_components)
        try:
            data = json.loads("\n".join(lines))
        except (json.JSONDecodeError, ValueError):
            return parse_component_list(lines)
    else:
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, ValueError):
            with open(path) as f:
                lines = f.readlines()
            if lines and all(len(line.strip().split("|")) in {4, 5} for line in lines if line.strip()):
                print("  Detected format: RPM manifest TSV", file=sys.stderr, flush=True)
                return parse_rpm_manifest(lines, direct_components=direct_components)
            return parse_component_list(lines)

    if isinstance(data, dict):
        if data.get("_type", "").startswith("https://in-toto.io/"):
            print("  Detected format: in-toto provenance", file=sys.stderr, flush=True)
            return parse_in_toto_provenance(data, direct_components=direct_components)
        if "artifacts" in data:
            print("  Detected format: Syft JSON", file=sys.stderr, flush=True)
            return parse_syft(data, direct_components=direct_components)
        if data.get("bomFormat") == "CycloneDX":
            print("  Detected format: CycloneDX JSON", file=sys.stderr, flush=True)
            return parse_cyclonedx(data, direct_components=direct_components)
        if "spdxVersion" in data or ("predicate" in data and "spdxVersion" in data.get("predicate", {})):
            print("  Detected format: SPDX 2.3 JSON", file=sys.stderr, flush=True)
            return parse_spdx(data, direct_components=direct_components)

    print("  Detected format: plain text component list", file=sys.stderr, flush=True)
    if isinstance(data, list):
        return parse_component_list([str(x) for x in data])
    return parse_component_list([])


# ---------------------------------------------------------------------------
# OSIDB query functions
# ---------------------------------------------------------------------------

def get_affects_for_component(base_url, module, component):
    url_template = (
        f"{base_url}/osidb/api/v1/affects?"
        f"ps_module={module}&ps_component={component}"
        f"&include_fields=uuid,flaw,ps_module,ps_component,affectedness,resolution,impact,trackers"
        f"&limit={{limit}}&offset={{offset}}"
    )
    affects = []
    for a in paginate(url_template):
        if a.get("affectedness") == "NOTAFFECTED":
            continue
        if a.get("resolution", "") not in OPEN_RESOLUTIONS:
            continue
        affects.append(a)
    return affects


def get_flaw_details(base_url, flaw_uuids):
    flaws = {}
    for uuid in flaw_uuids:
        url = (
            f"{base_url}/osidb/api/v1/flaws/{uuid}"
            f"?include_fields=uuid,cve_id,title,impact,workflow_state,source,cvss_scores"
        )
        try:
            flaw = fetch_json(url)
            if flaw.get("workflow_state") == "REJECTED":
                continue
            flaws[uuid] = flaw
        except Exception as e:
            print(f"  Warning: could not fetch flaw {uuid}: {e}", file=sys.stderr)
    return flaws


def get_rh_cvss(flaw):
    scores = flaw.get("cvss_scores", [])
    rh_scores = [s for s in scores if s.get("issuer") == "RH"]
    if not rh_scores:
        if scores:
            return max(float(s["score"]) for s in scores)
        return None
    for ver in ["V4", "V3", "V2"]:
        for s in rh_scores:
            if s.get("version") == ver:
                return float(s["score"])
    return float(rh_scores[0]["score"])


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_report(input_name, module, components_count, deduped, cve_groups, cve_info,
                  source=None, unknown=None, direct_components=False, component_label=None):
    print(f"# CVE Report")
    print()
    print(f"**Input:** {input_name}")
    print(f"**Module:** {module}")
    print(f"**Components scanned:** {components_count}")
    remediation_counts = defaultdict(int)
    if source == "OSIDB tracker":
        for affects in cve_groups.values():
            remediation_counts[cve_remediation_status(
                affect.get("remediation_status") for affect in affects
            )] += 1
    print(f"**CVEs found:** {len(cve_groups)}")
    if source == "OSIDB tracker":
        print(f"**Unfixed CVEs:** {remediation_counts['unfixed']}")
        print(f"**Fixed CVEs:** {remediation_counts['fixed']}")
        if remediation_counts["not a bug"]:
            print(f"**Not-a-bug CVEs:** {remediation_counts['not a bug']}")
    print(f"**Total component-affects:** {len(deduped)}")
    if source:
        print(f"**Source:** {source}")
    if unknown:
        print(f"**VEX state unavailable:** {len(unknown)} component build(s)")
    print()

    by_impact = defaultdict(list)
    for cve_id in cve_groups:
        info = cve_info[cve_id]
        by_impact[info["impact"]].append(cve_id)

    for imp in ["CRITICAL", "IMPORTANT", "MODERATE", "LOW", ""]:
        if imp not in by_impact:
            continue
        label = imp or "UNSET"
        cves = by_impact[imp]
        print(f"## {label} ({len(cves)})")
        print()
        is_vex = bool(source and source.startswith("Public Red Hat CSAF VEX"))
        status_label = "VEX status" if is_vex else "Image status"
        if direct_components:
            label = component_label or "SBOM component"
            print(f"| CVE | CVSS | {status_label} | Advisory | {label} | Component NVR |")
            print("|-----|------|--------------|----------|----------------|---------------|")
        else:
            print(f"| CVE | CVSS | {status_label} | Advisory | Image component (NVR) | Origin component (source NVR) | Upstream local |")
            print("|-----|------|--------------|----------|-----------------------|-------------------------------|-------------------------|")
        for cve_id in sorted(cves):
            info = cve_info[cve_id]
            origin_to_images = defaultdict(set)
            statuses = set()
            advisories = set()
            for affect in cve_groups[cve_id]:
                origin = affect.get("origin_component", affect["component"])
                origin_nvrs = tuple(sorted(affect.get("origin_nvrs", {origin})))
                upstream_streams = tuple(sorted(affect.get("upstream_streams", set())))
                origin_to_images[(origin_nvrs, upstream_streams)].update(
                    affect.get("image_components", {affect["component"]})
                )
                statuses.add(affect.get("remediation_status", affect["resolution"]))
                advisories.update(affect.get("advisories", []))
            origins = sorted(origin_to_images)
            component_cell = "<br>".join(
                ", ".join(sorted(origin_to_images[origin])) for origin in origins
            )
            origin_cell = "<br>".join(", ".join(origin_nvrs) for origin_nvrs, _ in origins)
            upstream_cell = "<br>".join(
                ", ".join(streams) if streams else "not found" for _, streams in origins
            )
            cvss_str = f"{info['cvss']:.1f}" if info["cvss"] is not None else "N/A"
            remediation_status = cve_remediation_status(statuses)
            fixed = remediation_status == "fixed"
            status_cell = remediation_status if source == "OSIDB tracker" else ", ".join(sorted(statuses))
            advisory_cell = ", ".join(sorted(advisories)) if fixed and advisories else "—"
            if direct_components:
                sbom_components = ", ".join(sorted({
                    affect.get("origin_component", affect["component"])
                    for affect in cve_groups[cve_id]
                }))
                print(f"| {cve_id} | {cvss_str} | {status_cell} | {advisory_cell} | {sbom_components} | {origin_cell} |")
            else:
                print(f"| {cve_id} | {cvss_str} | {status_cell} | {advisory_cell} | {component_cell} | {origin_cell} | {upstream_cell} |")
        print()

    if unknown:
        print("## VEX coverage gaps")
        print()
        print("No applicable public VEX state was found for these installed builds; they are "
              "unknown, not treated as not affected.")
        print()
        print("| Component | Installed NVR | Reason |")
        print("|-----------|---------------|--------|")
        for component, nvr, reason in sorted(unknown):
            print(f"| {component} | {nvr} | {reason} |")
        print()


def prepare_report(affect_details):
    """Deduplicate and group findings for reporting and CSAF VEX export."""
    seen = set()
    deduped = []
    for affect in affect_details:
        key = (affect["cve_id"], affect["component"])
        if key not in seen:
            seen.add(key)
            deduped.append(affect)
    impact_order = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "": 4}
    deduped.sort(key=lambda affect: (impact_order.get(affect["impact"], 5), affect["cve_id"]))
    cve_groups = defaultdict(list)
    cve_info = {}
    for affect in deduped:
        cve_groups[affect["cve_id"]].append(affect)
        cve_info.setdefault(affect["cve_id"], affect)
    return deduped, cve_groups, cve_info


def finish_report(input_name, module, components_count, affect_details, source=None, unknown=None,
                  direct_components=False, component_label=None):
    """Deduplicate, group, render, and return findings from either report source."""
    deduped, cve_groups, cve_info = prepare_report(affect_details)
    print(f"\n  {len(cve_groups)} unique CVEs across {len(deduped)} component-affects",
          file=sys.stderr, flush=True)
    render_report(
        input_name, module, components_count, deduped, cve_groups, cve_info,
        source, unknown, direct_components=direct_components, component_label=component_label,
    )
    return deduped, cve_groups, cve_info


def structured_report(input_name, module, components_count, deduped, cve_groups, cve_info,
                      source=None, unknown=None):
    """Return one browser-friendly row per CVE.

    Markdown remains the portable report format.  This representation keeps
    the same grouped data in a stable shape so local clients can filter and
    sort without scraping Markdown or making another tracker request.
    """
    findings = []
    for cve_id in sorted(cve_groups):
        info = cve_info[cve_id]
        origins = {}
        statuses = set()
        remediation_states = set()
        advisories = set()
        for affect in cve_groups[cve_id]:
            origin = affect.get("origin_component", affect["component"])
            key = (
                origin,
                tuple(sorted(affect.get("origin_nvrs", {origin}))),
                tuple(sorted(affect.get("upstream_streams", set()))),
                affect.get("remediation_status"),
                tuple(sorted(affect.get("advisories", []))),
            )
            origins.setdefault(key, set()).update(affect.get("image_components", {affect["component"]}))
            statuses.add(affect.get("resolution", ""))
            if affect.get("remediation_status"):
                remediation_states.add(affect["remediation_status"])
            advisories.update(affect.get("advisories", []))
        remediation_status = cve_remediation_status(remediation_states)
        findings.append({
            "cveId": cve_id,
            "impact": info.get("impact", "") or "UNSET",
            "cvss": info.get("cvss"),
            "status": sorted(status for status in statuses if status),
            "remediationStatus": remediation_status,
            "advisories": sorted(advisories) if remediation_status == "fixed" else [],
            "title": info.get("title", ""),
            "components": [
                {
                    "originComponent": origin,
                    "originNvrs": list(origin_nvrs),
                    "imageComponents": sorted(image_components),
                    "upstreamStreams": list(streams),
                    "remediationStatus": component_status,
                    "advisories": list(component_advisories),
                }
                for (origin, origin_nvrs, streams, component_status, component_advisories), image_components
                in sorted(origins.items())
            ],
        })
    fixed_cves = sum(finding["remediationStatus"] == "fixed" for finding in findings)
    unfixed_cves = sum(finding["remediationStatus"] == "unfixed" for finding in findings)
    return {
        "schema": "cve-report-results/v1",
        "summary": {
            "input": input_name,
            "module": module,
            "componentsScanned": components_count,
            "unresolvedCves": unfixed_cves if source == "OSIDB tracker" else len(cve_groups),
            "fixedCves": fixed_cves,
            "unfixedCves": unfixed_cves,
            "componentAffects": len(deduped),
            "source": source or "OSIDB tracker",
            "vexCoverageGaps": len(unknown or []),
        },
        "findings": findings,
        "unknown": [
            {"component": component, "installedNvr": nvr, "reason": reason}
            for component, nvr, reason in sorted(unknown or [])
        ],
    }


def write_structured_report(path, report):
    """Write the optional machine-readable companion to the Markdown report."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CSAF VEX export
# ---------------------------------------------------------------------------

def vex_stream_from_nvr(module, nvr):
    """Return the GA VEX RHEL stream identifier for an installed source NVR."""
    major_match = re.fullmatch(r"rhel-(\d+)", module)
    if not major_match:
        return module
    major = major_match.group(1)
    minor = rhel_minor_from_nvr(nvr or "")
    return f"rhel-{major}.{minor}.z"


def vex_stream_cpe(stream):
    """Build the RHEL CPE convention used by the GA public VEX feed."""
    match = re.fullmatch(r"rhel-(\d+)(?:\.(\d+))?\.z", stream)
    if not match:
        return ""
    major, minor = match.groups()
    return f"cpe:/o:redhat:enterprise_linux:{major}.{minor or '0'}"


def vex_component(component, nvr=None):
    """Return a GA VEX source-RPM product node for an installed NVR.

    Public GA VEX keeps the component display name versionless, but includes
    the source architecture and explicit epoch in its product ID and purl.
    """
    parsed = split_rpm_nvr(nvr) if nvr else None
    name, evr = parsed if parsed else (component, None)
    if nvr and not parsed:
        raise ValueError(f"Cannot create a VEX RPM product from {nvr!r}")
    purl_name = urllib.parse.quote(name, safe=".+-_")
    if not evr:
        return name, {
            "category": "product_version",
            "name": name,
            "product": {
                "name": name,
                "product_id": name,
                "product_identification_helper": {
                    "purl": f"pkg:rpm/redhat/{purl_name}?arch=src",
                },
            },
        }
    epoch, version, release = split_evr(evr)
    version_release = f"{version}-{release}" if release else version
    component_id = f"{name}-{epoch}:{version_release}.src"
    purl_version = urllib.parse.quote(version_release, safe=".+~^:-_")
    return component_id, {
        "category": "product_version",
        "name": name,
        "product": {
            "name": name,
            "product_id": component_id,
            "product_identification_helper": {
                "purl": f"pkg:rpm/redhat/{purl_name}@{purl_version}?arch=src&epoch={epoch}",
            },
        },
    }


def vex_status(status):
    """Map report evidence to a valid CSAF product-status bucket."""
    allowed = {"fixed", "first_affected", "first_fixed", "known_affected",
               "known_not_affected", "last_affected", "recommended",
               "under_investigation"}
    return status if status in allowed else "known_affected"


def vex_disposition(affect):
    """Return a remediation disposition without conflating it with status."""
    if affect.get("disposition"):
        return affect["disposition"]
    # OSIDB workflow terms are not CSAF product-status values.  DEFER means
    # affected with no planned fix; DELEGATED remains affected while the
    # owning product team works the remediation.
    if affect.get("resolution", "").upper() == "DEFER":
        return "deferred / no fix available"
    return ""


def vex_document(cve_groups, module, input_name, generated_at):
    """Build one input-scoped CSAF 2.0 VEX document for an SBOM.

    The component structure follows the Red Hat GA VEX convention.  Unlike
    Red Hat's public portfolio feed (one document per CVE), this local output
    intentionally bundles all report findings for one scanned SBOM.
    """
    component_nodes = {}
    product_nodes = {}
    relationships = {}
    vulnerabilities = []
    impacts = []

    for cve_id, affects in sorted(cve_groups.items()):
        product_status = defaultdict(set)
        remediation_products = defaultdict(set)
        for affect in affects:
            status = vex_status(affect.get("resolution", ""))
            disposition = vex_disposition(affect)
            origin_nvrs = affect.get("origin_nvrs") or [None]
            for nvr in origin_nvrs:
                try:
                    component_id, component_node = vex_component(
                        affect.get("origin_component") or affect["component"], nvr
                    )
                except ValueError:
                    continue
                component_nodes[component_id] = component_node
                streams = affect.get("upstream_streams") or [vex_stream_from_nvr(module, nvr)]
                for stream in streams:
                    product_nodes[stream] = {
                        "category": "product_name",
                        "name": f"Red Hat Enterprise Linux {stream.removeprefix('rhel-')}",
                        "product": {
                            "name": f"Red Hat Enterprise Linux {stream.removeprefix('rhel-')}",
                            "product_id": stream,
                            "product_identification_helper": {"cpe": vex_stream_cpe(stream)},
                        },
                    }
                    relationship_id = f"{stream}:{component_id}"
                    relationships[relationship_id] = {
                        "category": "default_component_of",
                        "full_product_name": {
                            "name": f"{component_node['name']} as a component of "
                                    f"Red Hat Enterprise Linux {stream.removeprefix('rhel-')}",
                            "product_id": relationship_id,
                        },
                        "product_reference": component_id,
                        "relates_to_product_reference": stream,
                    }
                    product_status[status].add(relationship_id)
                    if disposition:
                        remediation_products[disposition].add(relationship_id)

        info = affects[0]
        vulnerability = {
            "cve": cve_id,
            "title": info.get("title") or cve_id,
            "product_status": {status: sorted(ids) for status, ids in sorted(product_status.items())},
        }
        impact = (info.get("impact") or "").title()
        if impact:
            impacts.append(impact.upper())
            vulnerability["threats"] = [{
                "category": "impact", "details": impact,
                "product_ids": sorted({item for ids in product_status.values() for item in ids}),
            }]
        if remediation_products:
            vulnerability["remediations"] = [
                {
                    "category": "none_available" if disposition == "deferred / no fix available" else "workaround",
                    "details": disposition.replace(" / ", "; ").title(),
                    "product_ids": sorted(product_ids),
                }
                for disposition, product_ids in sorted(remediation_products.items())
            ]
        vulnerabilities.append(vulnerability)

    timestamp = generated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    document_id = uuid.uuid5(uuid.NAMESPACE_URL, f"cve-report:{module}:{input_name}")
    document = {
        "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/json_schema/csaf_json_schema.json",
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "publisher": {
                "category": "user",
                "contact_details": "Local analysis generated by cve-report.",
                "name": VEX_EXPORT_ENGINE,
                "namespace": "https://www.redhat.com",
            },
            "title": f"Local VEX for {Path(input_name).name}",
            "tracking": {
                "current_release_date": timestamp,
                "generator": {
                    "date": timestamp,
                    "engine": {"name": VEX_EXPORT_ENGINE, "version": VEX_EXPORT_VERSION},
                },
                "id": f"urn:uuid:{document_id}",
                "initial_release_date": timestamp,
                "revision_history": [{"date": timestamp, "number": "1", "summary": "Last generated version"}],
                "status": "final",
                "version": "1",
            },
        },
        "product_tree": {
            "branches": [{
                "category": "vendor",
                "name": "Red Hat",
                "branches": [product_nodes[key] for key in sorted(product_nodes)]
                            + [component_nodes[key] for key in sorted(component_nodes)],
            }],
            "relationships": [relationships[key] for key in sorted(relationships)],
        },
        "vulnerabilities": vulnerabilities,
    }
    impact_order = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3}
    if impacts:
        document["document"]["aggregate_severity"] = {
            "namespace": "https://access.redhat.com/security/updates/classification/",
            "text": min(impacts, key=lambda impact: impact_order.get(impact, 4)).title(),
        }
    return document


def default_vex_output_path(input_path):
    """Return a reproducible, adjacent output file for a file input."""
    if input_path == "-":
        return None
    path = Path(input_path)
    return path.with_name(f"{path.name}.vex.json")


def write_vex_document(output_path, input_name, module, cve_groups):
    """Write the one input-scoped CSAF VEX document for an SBOM."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(vex_document(cve_groups, module, input_name, datetime.now(timezone.utc)), indent=2) + "\n"
    )
    print(f"  CSAF VEX: wrote {len(cve_groups)} CVE(s) to {output_path}",
          file=sys.stderr, flush=True)


def confirm_scanner_image(report_path, architecture, supplied_image, accept_suggestion):
    """Require an explicit choice before correlating scanner rows to an image."""
    if supplied_image:
        scanner_csv.parse_image_reference(supplied_image)
        return supplied_image
    candidates = scanner_csv.suggest_image_candidates(report_path, architecture)
    print("\nSuggested Red Hat Catalog image matches:", file=sys.stderr, flush=True)
    for number, candidate in enumerate(candidates, start=1):
        print(f"  {number}. {candidate.reference} (score {candidate.score}/100)", file=sys.stderr, flush=True)
        for reason in candidate.reasons:
            print(f"     - {reason}", file=sys.stderr, flush=True)
    if accept_suggestion:
        print(f"  Accepting highest-ranked candidate: {candidates[0].reference}", file=sys.stderr, flush=True)
        return candidates[0].reference
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Scanner findings review requires an explicit image confirmation. "
            "Use --image <reference> or --confirm-image to accept the highest-ranked Catalog candidate."
        )
    answer = input("Select a candidate number, or enter an exact tagged image (blank cancels): ").strip()
    if answer.isdigit() and 1 <= int(answer) <= len(candidates):
        return candidates[int(answer) - 1].reference
    if answer:
        scanner_csv.parse_image_reference(answer)
        return answer
    raise RuntimeError("No image was selected; scanner findings review was cancelled.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Query OSIDB for unresolved CVEs affecting packages in an SBOM or component list.",
    )
    parser.add_argument(
        "input",
        help="Path to SBOM file (SPDX, CycloneDX, Syft JSON) or plain text component list, or '-' for stdin",
    )
    parser.add_argument(
        "--scanner-review", action="store_true",
        help="Treat input as a vulnerability scanner report and confirm a Red Hat Catalog image before analysis.",
    )
    parser.add_argument(
        "--image",
        help="Explicit tagged or digest-pinned scanned image for --scanner-review; this is treated as user confirmation.",
    )
    parser.add_argument(
        "--image-architecture", choices=sorted(scanner_csv.ARCHITECTURES), default="amd64",
        help="Image architecture used for Catalog matching during --scanner-review (default: amd64).",
    )
    parser.add_argument(
        "--confirm-image", action="store_true",
        help="For non-interactive --scanner-review, accept the highest-ranked Catalog candidate.",
    )
    parser.add_argument(
        "--module",
        help="OSIDB ps_module to query (e.g. rhel-8, rhel-9). Auto-detected from input if omitted.",
    )
    parser.add_argument("--env", choices=["prod", "uat"], default="prod")
    parser.add_argument("--workers", type=int, default=4, help="Max parallel API workers")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--osidb", dest="source", action="store_const", const="osidb", default="osidb",
                        help="Use OSIDB tracker data (default).")
    source.add_argument("--vex", dest="source", action="store_const", const="vex",
                        help="Use the local public CSAF VEX index.")
    parser.add_argument(
        "--vex-direct-components",
        action="store_true",
        help="For --vex, match the SBOM's RPM component names directly and skip BOMQ origin mapping.",
    )
    parser.add_argument(
        "--pyxis-image",
        help=("Immutable Red Hat registry image digest used with --vex-direct-components to "
              "map exact SBOM RPMs to source RPMs from its Pyxis manifest."),
    )
    parser.add_argument(
        "--pyxis-architecture", choices=sorted(scanner_csv.ARCHITECTURES), default="amd64",
        help="Architecture for --pyxis-image (default: amd64).",
    )
    parser.add_argument("--sync-vex", action="store_true", help="Incrementally refresh the local CSAF VEX index before a --vex report.")
    parser.add_argument("--vex-cache",
                        help="Path to the shared local VEX SQLite index (default: .cache/vex.sqlite3).")
    parser.add_argument("--report-json",
                        help="Write a structured JSON companion to the Markdown report.")
    parser.add_argument("--only-cves-file",
                        help="Limit the report and derived VEX to CVE IDs listed one per line in this file.")
    parser.add_argument("--only-components-file",
                        help="Limit OSIDB/BOMQ lookups to scanner package names listed one per line in this file.")
    parser.add_argument(
        "--bomq-stream",
        help="BOMQ stream used to verify installed source builds (for example rhel-10.2.z).",
    )
    parser.add_argument(
        "--bomq-cache",
        help="Path to the local immutable source-build BOMQ cache (default: one cache per RHEL major).",
    )
    vex_output = parser.add_mutually_exclusive_group()
    vex_output.add_argument(
        "--vex-output",
        help="Path for generated CSAF VEX document (default: <input>.vex.json).",
    )
    vex_output.add_argument(
        "--no-vex-output", action="store_true",
        help="Do not generate the local CSAF VEX document alongside the report.",
    )
    args = parser.parse_args()

    try:
        only_cves = load_cve_filter(args.only_cves_file)
        only_components = load_component_filter(args.only_components_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if args.sync_vex and args.source != "vex":
        parser.error("--sync-vex requires --vex")
    if args.vex_direct_components and args.source != "vex":
        parser.error("--vex-direct-components requires --vex")
    if args.vex_direct_components and args.bomq_stream:
        parser.error("--vex-direct-components cannot be combined with --bomq-stream")
    if args.pyxis_image and (args.source != "vex" or not args.vex_direct_components):
        parser.error("--pyxis-image requires --vex --vex-direct-components")
    if args.pyxis_image:
        try:
            _, _, _, pyxis_digest = scanner_csv.parse_image_reference(args.pyxis_image)
        except scanner_csv.ScannerInputError as exc:
            parser.error(str(exc))
        if not pyxis_digest:
            parser.error("--pyxis-image requires an immutable registry digest (…@sha256:<digest>)")
    if (args.image or args.confirm_image) and not args.scanner_review:
        parser.error("--image and --confirm-image require --scanner-review")

    base_url = ENVS[args.env]
    input_name = args.input if args.input != "-" else "stdin"

    if args.scanner_review:
        if args.input == "-":
            parser.error("--scanner-review requires a report file so its name can be matched to Catalog metadata")
        try:
            reference = confirm_scanner_image(
                args.input, args.image_architecture, args.image, args.confirm_image,
            )
            source = Path(args.input)
            catalog_sbom = source.with_name(f"{source.name}.catalog-sbom.cdx.json")
            scanner_evidence = source.with_name(f"{source.name}.scanner-evidence.json")
            subject, _ = scanner_csv.prepare_scanner_analysis(
                source, reference, args.image_architecture, catalog_sbom, scanner_evidence,
            )
            print(f"\nConfirmed image: {subject.resolved_reference}", file=sys.stderr, flush=True)
            print(f"  Catalog-derived SBOM: {catalog_sbom}", file=sys.stderr, flush=True)
            print(f"  Scanner provenance evidence: {scanner_evidence}", file=sys.stderr, flush=True)
            args.input = str(catalog_sbom)
        except (RuntimeError, scanner_csv.ScannerInputError) as exc:
            parser.error(str(exc))

    print(f"Parsing input: {input_name}", file=sys.stderr, flush=True)
    components, detected_module, component_nvrs, component_origins = parse_input(
        args.input, direct_components=args.vex_direct_components
    )

    pyxis_stream_hints = {}
    pyxis_subject = None
    pyxis_matched = pyxis_unmatched = 0
    if args.pyxis_image:
        print("  Resolving the exact registry image and RPM manifest from Pyxis...",
              file=sys.stderr, flush=True)
        try:
            (components, component_nvrs, component_origins, pyxis_stream_hints,
             pyxis_subject, pyxis_matched, pyxis_unmatched) = map_vex_components_to_pyxis_sources(
                args.pyxis_image, args.pyxis_architecture, component_nvrs
            )
        except scanner_csv.ScannerInputError as exc:
            parser.error(str(exc))
        print(f"  Pyxis image: {pyxis_subject.resolved_reference}", file=sys.stderr, flush=True)
        print(f"  Pyxis source-RPM mapping: {pyxis_matched} exact SBOM RPM(s), "
              f"{pyxis_unmatched} SBOM fallback(s)", file=sys.stderr, flush=True)

    if not components:
        print("ERROR: No components found in input.", file=sys.stderr)
        sys.exit(1)

    module = args.module or detected_module
    if not module:
        print("ERROR: Could not auto-detect RHEL version. Use --module to specify.", file=sys.stderr)
        sys.exit(1)

    if only_components is not None:
        all_components = set(components)
        components = select_scanner_components(all_components, component_origins, only_components)
        component_nvrs = {component: component_nvrs[component] for component in components}
        component_origins = {component: component_origins[component] for component in components}
        print(f"  Scanner package filter selected {len(components)}/{len(all_components)} "
              f"origin component(s).", file=sys.stderr, flush=True)
    if not args.vex_cache:
        args.vex_cache = str(Path(__file__).parent / ".cache" / "vex.sqlite3")
    if not args.vex_direct_components and not args.bomq_cache:
        args.bomq_cache = str(Path(__file__).parent / ".cache" / f"bomq-{module}.json")
    if not args.no_vex_output:
        args.vex_output = args.vex_output or default_vex_output_path(args.input)
        if not args.vex_output:
            parser.error("--vex-output is required when input is stdin (or use --no-vex-output)")

    components = sorted(components)
    print(f"\n  {len(components)} components: {', '.join(components[:20])}"
          f"{'...' if len(components) > 20 else ''}", file=sys.stderr, flush=True)
    print(f"  Module: {module}", file=sys.stderr, flush=True)

    if args.bomq_stream:
        source_builds = sorted({
            (component, nvr)
            for component, nvrs in component_nvrs.items()
            for nvr in nvrs
        })
        if not source_builds:
            print("  BOMQ origin check skipped: input has no RPM NVRs", file=sys.stderr, flush=True)
        else:
            print(f"  Verifying {len(source_builds)} source builds in BOMQ stream {args.bomq_stream}...", file=sys.stderr, flush=True)
            unverified = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, BOMQ_WORKERS)) as ex:
                futures = {
                    ex.submit(bomq_has_source_build, args.bomq_stream, component, nvr): (component, nvr)
                    for component, nvr in source_builds
                }
                for future in concurrent.futures.as_completed(futures):
                    source_build = futures[future]
                    try:
                        if not future.result():
                            unverified.append(source_build)
                    except Exception as exc:
                        unverified.append(source_build)
                        print(f"  BOMQ lookup failed for {source_build[1]}: {exc}", file=sys.stderr, flush=True)
            if unverified:
                examples = ", ".join(nvr for _, nvr in sorted(unverified)[:5])
                print(f"  WARNING: {len(unverified)} source build(s) were not found in BOMQ: {examples}", file=sys.stderr, flush=True)
            else:
                print("  BOMQ origin check: all source builds found", file=sys.stderr, flush=True)

    if args.source == "vex":
        if not component_nvrs:
            parser.error("--vex requires RPM NVRs; provide an RPM manifest or an SBOM with RPM versions")
        upstream_origins = {}
        if args.vex_direct_components:
            if args.pyxis_image:
                print("\nUsing Pyxis image-manifest source-RPM mapping; BOMQ origin mapping is disabled.",
                      file=sys.stderr, flush=True)
            else:
                # VEXScope deliberately assesses the package names supplied by
                # the SBOM.  No source-RPM aliases or BOMQ stream data take part.
                component_origins = {}
                print("\nUsing SBOM RPM component names directly; BOMQ origin mapping is disabled.",
                      file=sys.stderr, flush=True)
        else:
            source_builds = sorted({
                (component, nvr)
                for component, nvrs in component_nvrs.items()
                for nvr in nvrs
            })
            bomq_entries = load_bomq_cache(args.bomq_cache)
            pending_bomq = []
            for component, nvr in source_builds:
                cached = cached_bomq_origin_streams(bomq_entries, module, component, nvr)
                if cached is None:
                    pending_bomq.append((component, nvr))
                else:
                    upstream_origins[(component, nvr)] = cached
            print(f"\nResolving BOMQ upstream streams for {len(source_builds)} source build(s) "
                  f"({len(upstream_origins)} cached; {len(pending_bomq)} request(s), max {BOMQ_WORKERS} concurrent)...",
                  file=sys.stderr, flush=True)
            cache_changed = False
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(BOMQ_WORKERS, max(1, len(pending_bomq)))) as executor:
                futures = {
                    executor.submit(bomq_origin_streams, module, component, nvr): (component, nvr)
                    for component, nvr in pending_bomq
                }
                for future in concurrent.futures.as_completed(futures):
                    source_build = futures[future]
                    try:
                        streams = future.result()
                        upstream_origins[source_build] = streams
                        cache_bomq_origin_streams(bomq_entries, module, *source_build, streams)
                        cache_changed = True
                    except Exception as exc:
                        upstream_origins[source_build] = set()
                        print(f"  BOMQ origin lookup failed for {source_build[1]}: {exc}",
                              file=sys.stderr, flush=True)
            if cache_changed:
                save_bomq_cache(args.bomq_cache, bomq_entries)
        if args.sync_vex:
            print("\nRefreshing public CSAF VEX cache...", file=sys.stderr, flush=True)
            vex_cache.sync(args.vex_cache, module, workers=min(args.workers, 8))
        print("\nQuerying local public CSAF VEX index...", file=sys.stderr, flush=True)
        try:
            affect_details, unknown = vex_cache.findings(
                args.vex_cache, component_nvrs, module, compare_evr, args.bomq_stream,
                component_origins, upstream_origins, pyxis_stream_hints
            )
            vex_source = "Public Red Hat CSAF VEX"
            component_label = None
            if args.pyxis_image:
                vex_source += " (Pyxis image-manifest source mapping)"
                component_label = "Pyxis source component (SBOM fallback)"
            elif args.vex_direct_components:
                vex_source += " (direct SBOM component match)"
            deduped, cve_groups, cve_info = finish_report(
                input_name, module, len(components), affect_details,
                source=vex_source, unknown=unknown,
                direct_components=args.vex_direct_components,
                component_label=component_label,
            )
            if args.report_json:
                write_structured_report(
                    args.report_json,
                    structured_report(input_name, module, len(components), deduped, cve_groups,
                                      cve_info, source=vex_source, unknown=unknown),
                )
            if not args.no_vex_output:
                write_vex_document(args.vex_output, input_name, module, cve_groups)
        except RuntimeError as exc:
            parser.error(str(exc))
        return

    upstream_origins = resolve_bomq_origin_streams(module, component_nvrs, args.bomq_cache)

    query_label = "scanner-associated origin components" if only_components is not None else "all image origin components"
    print(f"\nQuerying OSIDB ({args.env}) for unresolved affects on {query_label} in {module}...",
          file=sys.stderr, flush=True)
    all_affects = []
    flaw_to_components = defaultdict(set)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(get_affects_for_component, base_url, module, c): c for c in components}
        for f in concurrent.futures.as_completed(futures):
            comp = futures[f]
            try:
                affects = f.result()
            except Exception as e:
                print(f"  {comp}: ERROR - {e}", file=sys.stderr, flush=True)
                continue
            print(f"  {comp}: {len(affects)} open affects", file=sys.stderr, flush=True)
            for a in affects:
                flaw_to_components[a["flaw"]].add(comp)
            all_affects.extend(affects)

    if not all_affects:
        print("\nNo unresolved CVEs found.", file=sys.stderr)
        print(f"# Unresolved CVEs Report\n")
        print(f"**Input:** {input_name}")
        print(f"**Module:** {module}")
        print(f"**Components scanned:** {len(components)}")
        print(f"**Unresolved CVEs found:** 0")
        if args.report_json:
            write_structured_report(
                args.report_json,
                structured_report(input_name, module, len(components), [], {}, {}, source="OSIDB tracker"),
            )
        if not args.no_vex_output:
            write_vex_document(args.vex_output, input_name, module, {})
        return

    flaw_uuids = list(flaw_to_components.keys())
    print(f"\nFetching details for {len(flaw_uuids)} unique flaws...", file=sys.stderr, flush=True)

    flaws = {}
    batch_size = 20
    for i in range(0, len(flaw_uuids), batch_size):
        batch = flaw_uuids[i:i + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(get_flaw_details, base_url, [u]): u for u in batch}
            for f in concurrent.futures.as_completed(futures):
                flaws.update(f.result())
        done = min(i + batch_size, len(flaw_uuids))
        print(f"  Fetched {done}/{len(flaw_uuids)} flaws...", file=sys.stderr, flush=True)

    cve_ids = {cve_id for flaw in flaws.values()
               if (cve_id := canonical_cve_id(flaw.get("cve_id")))}
    print(f"  Fetching public fixed-build data for {len(cve_ids)} CVEs...", file=sys.stderr, flush=True)
    security_data = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, 8)) as ex:
        futures = {ex.submit(fetch_security_data, cve_id): cve_id for cve_id in cve_ids}
        for future in concurrent.futures.as_completed(futures):
            cve_id = futures[future]
            try:
                security_data[cve_id] = future.result()
            except Exception as exc:
                print(f"  {cve_id}: public security-data lookup failed: {exc}", file=sys.stderr, flush=True)

    vex_origin_statuses = {}
    vex_candidates = {
        (canonical_cve_id(flaws[a["flaw"]].get("cve_id")), a["ps_component"])
        for a in all_affects
        if a["flaw"] in flaws and canonical_cve_id(flaws[a["flaw"]].get("cve_id"))
    }
    if vex_candidates and Path(args.vex_cache).exists():
        print(f"  Reconciling {len(vex_candidates)} OSIDB origin affect(s) against the local VEX cache...",
              file=sys.stderr, flush=True)
        try:
            vex_origin_statuses = vex_cache.fixed_component_statuses(
                args.vex_cache, component_nvrs, vex_candidates, module, compare_evr,
                component_origins, upstream_origins,
            )
            print(f"  Public VEX confirms {len(vex_origin_statuses)} origin component(s) as fixed or not a bug.",
                  file=sys.stderr, flush=True)
        except (RuntimeError, sqlite3.Error) as exc:
            print(f"  VEX reconciliation skipped: {exc}", file=sys.stderr, flush=True)
    elif vex_candidates:
        print("  VEX reconciliation skipped: local VEX cache is not available.",
              file=sys.stderr, flush=True)

    affect_details = []
    for a in all_affects:
        flaw = flaws.get(a["flaw"])
        if not flaw:
            continue
        cve_id = canonical_cve_id(flaw.get("cve_id"))
        # This is a CVE report.  A flaw without a public CVE cannot be
        # reconciled with Red Hat's public fixed-build data and must not be
        # presented as a CVE-shaped UUID.
        if not cve_id:
            continue
        component = a["ps_component"]
        fixed, fixed_reason, advisories = component_status_from_security_data(
            security_data.get(cve_id), module, component, component_nvrs.get(component, set())
        )
        affect_status = origin_affect_status(a)
        vex_status = vex_origin_statuses.get((cve_id, component))
        remediation_status = vex_status or affect_status or ("fixed" if fixed else "unfixed")
        origin_nvrs = sorted(component_nvrs.get(component, set()))
        upstream_streams = sorted({
            stream
            for nvr in origin_nvrs
            for stream in upstream_origins.get((component, nvr), set())
        })
        affect_details.append({
            "cve_id": cve_id,
            "impact": flaw.get("impact") or a.get("impact") or "",
            "cvss": get_rh_cvss(flaw),
            "title": flaw.get("title", ""),
            "component": component,
            "affectedness": a.get("affectedness", ""),
            "resolution": a.get("resolution", "") or "(none)",
            "remediation_status": remediation_status,
            "remediation_reason": (
                "public VEX confirms the installed origin build" if vex_status else fixed_reason
            ),
            "advisories": sorted(advisories),
            "workflow_state": flaw.get("workflow_state", ""),
            "origin_component": component,
            "origin_nvrs": origin_nvrs,
            "image_components": sorted(component_origins.get(component, {component})),
            "upstream_streams": upstream_streams,
        })

    if only_cves is not None:
        before = len(affect_details)
        affect_details = [affect for affect in affect_details if affect["cve_id"] in only_cves]
        print(f"  Limited scanner review to {len(only_cves)} reported CVE(s): "
              f"{len(affect_details)}/{before} component-affects retained.",
              file=sys.stderr, flush=True)

    deduped, cve_groups, cve_info = finish_report(
        input_name, module, len(components), affect_details, source="OSIDB tracker"
    )
    if args.report_json:
        write_structured_report(
            args.report_json,
            structured_report(input_name, module, len(components), deduped, cve_groups, cve_info,
                              source="OSIDB tracker"),
        )
    if not args.no_vex_output:
        write_vex_document(args.vex_output, input_name, module, cve_groups)


if __name__ == "__main__":
    main()
