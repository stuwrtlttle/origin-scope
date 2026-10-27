# Public VEX mode

## Decision

Use Red Hat's public binary-RPM-aware GA CSAF VEX distribution as the source
of truth in VEX mode.
Do not scan a directory of JSON documents on each report run.

The feed exposes an incremental change list at:

`https://security.access.redhat.com/data/csaf/v2/vex-feed/changes.csv`

Each listed document contains product-tree PURLs/CPEs and per-CVE product
statuses.  BOMQ remains the provenance authority for the image component and
origin stream; VEX provides the public vulnerability state for that exact
component/build relationship.

## Cache

The cache is a SQLite database outside Git, shared across all public Red Hat
products (`.cache/vex.sqlite3` by default). The query path selects the relevant
product stream from BOMQ provenance; it does not rebuild the cache per RHEL major.
It stores normalized relationships rather than the full CSAF document corpus:

| Table | Key | Purpose |
| --- | --- | --- |
| `documents` | `uri` | Feed timestamp for a successfully normalized document |
| `unavailable_documents` | `uri` | Feed paths confirmed withdrawn (HTTP 404), to avoid repeat requests |
| `cache_metadata` | `key` | Feed identity, schema, build state, and last successful synchronization |
| `rpm_status` | `uri, cve_id, component, evr, stream, status` | Query-ready index derived from CSAF product IDs |

`changes.csv` is the synchronization cursor. A refresh downloads only new or
changed documents, retains all product streams, replaces a document's normalized
rows transactionally, and indexes `rpm_status(component, stream)`. The initial
build streams the published compressed archive, then catches up documents absent
from that archive. Committed batches make an interrupted initial build resumable.

## Query path

1. Parse the image manifest into source component + installed NEVR.
2. Resolve BOMQ provenance and the relevant RHEL stream.
3. Join image components to `rpm_status` on component and stream, preferring
   exact NEVR rows over generic component rows.
4. Report only `known_affected` / investigation rows whose VEX state applies
   to the installed build.  Suppress exact `known_not_affected` and `fixed`
   rows.

The initial VEX sync is intentionally a one-time bulk operation. Subsequent
reports use only local SQLite lookups; updates are proportional to the feed's
changed documents. In the browser app, cache update/rebuild is a top-level
maintenance action and never an implicit part of an analysis run.

## CLI

The target interface is mutually exclusive source selection:

```sh
cve-report IMAGE_SBOM --osidb
cve-report IMAGE_SBOM --vex --sync-vex
```

`--osidb` retains the current authenticated OSIDB tracker workflow.
`--vex` works from the public CSAF cache and requires no OSIDB access.

## Local CSAF VEX output

The checker writes one input-scoped CSAF VEX document for each SBOM by default
at `<input>.vex.json`. Its `vulnerabilities` array contains every unresolved
CVE in the report. `--vex-output` overrides that path and `--no-vex-output`
disables generation.

The component and product representation follows the current public Red Hat GA
VEX convention: a flat `Red Hat` vendor branch; RHEL minor stream CPEs;
versionless source component names; RPM PURLs with explicit epochs; and
`default_component_of` relationships. The document uses a deterministic UUID
derived from the input and module, and declares `cve-report` as a local `user`
publisher. It is therefore interoperable CSAF VEX, but not an official,
portfolio-wide Red Hat VEX publication.

## Safety rules

- Exact source/binary NEVR states take precedence over generic component
  states.
- A newer stream's VEX state never resolves an image from an earlier stream.
- A missing VEX record is reported as `unknown`; it is never silently treated
  as not affected.
- Cache artifacts and downloaded documents are ignored by Git.
