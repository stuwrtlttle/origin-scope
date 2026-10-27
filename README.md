# OriginScope

OriginScope is the holistic image-reporting workbench. It accepts an SBOM or
RPM inventory, evaluates the full component set against OSIDB, public Red Hat
VEX, and BOMQ provenance, then produces a Markdown report, structured JSON,
and a local CSAF VEX document.

It deliberately does not offer scanner-report ingestion or Catalog image
matching. Use SignalTrace for that workflow.

## Run

```sh
python3 originscope_app.py
```

The app binds only to `127.0.0.1:8765` by default and stores run data in
`~/.cache/origin-scope/`.

## Assessment profiles and evidence

OriginScope applies a versioned assessment profile to each analysis. Select
**Report only** to retain the full posture without gating, or **Critical
exposure gate** to fail the policy verdict when an active Critical CVE remains.
The built-in, reviewable profile catalog is
[`assessment_profiles.json`](assessment_profiles.json); it also supports
time-limited, reasoned CVE waivers.

Each completed run offers an `assessment-bundle.json` download. It records the
selected profile and its fully expanded rules, rule-level `pass`, `fail`,
`unknown`, `not_applicable`, or `waived` states, the overall policy verdict,
the results summary, VEX/BOMQ cache provenance, and SHA-256 hashes for the
input and generated artifacts. The app finalizes this bundle read-only in the
run directory, so it is a portable, tamper-evident record of the assessment.

## VEX-only workbench

VEXScope evaluates SBOMs and RPM inventories exclusively against the public
Red Hat CSAF VEX feed; it makes no OSIDB or BOMQ queries. It matches the RPM
component name and build supplied by the SBOM directly. It runs on port 8766
by default, falling back to an available localhost port when 8766 is occupied,
and uses `~/.cache/vexscope/` for run data.

Optionally provide a published Red Hat image pinned by registry digest in the
VEXScope form. VEXScope resolves that exact image in Pyxis, retrieves its RPM
manifest, and maps exact SBOM RPM matches to their source RPMs. Packages not
present in the manifest remain direct SBOM matches; this is image-manifest
provenance, not BOMQ release-stream provenance.

```sh
python3 vexscope_app.py
```

Build the local VEX cache from VEXScope before its first analysis, then use
Update to fetch only changed public records.

To hand VEXScope to someone else, create a portable runtime bundle:

```sh
python3 package_vexscope.py
```

This writes `vexscope-bundle.tar.gz` in the current directory.

## CLI

```sh
python3 cve_report.py image.sbom.json --vex
```

The local public VEX cache is shared only within this project at
`.cache/vex.sqlite3`. See [the VEX design](docs/vex-design.md) for matching
rules and generated-VEX structure.
