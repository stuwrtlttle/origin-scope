#!/usr/bin/env python3
"""OriginScope: focused holistic image/SBOM reporting workbench."""

import argparse
import html
from pathlib import Path
import webbrowser

import assessment_policy
import cve_report_app as workbench


def validate_options(payload):
    if not isinstance(payload, dict):
        raise ValueError("Configuration must be an object.")
    if payload.get("analysisMode") not in (None, "holistic"):
        raise ValueError("OriginScope accepts SBOM or RPM inventory analysis only.")
    return _base_validate({**payload, "analysisMode": "holistic"})


def default_data_dir():
    return Path.home() / ".cache" / "origin-scope"


_base_validate = workbench.validate_options
_profile_options = "".join(
    f'<option value="{html.escape(item["id"])}">{html.escape(item["name"])} — v{html.escape(item["version"])}</option>'
    for item in assessment_policy.profile_options()
)
_assessment_profile_fields = (
    '<div class="fields" id="assessment-profile-fields"><label>Assessment profile'
    f'<select id="assessment-profile">{_profile_options}</select></label>'
    '<p class="hint">Profiles are versioned release-policy definitions. Every run retains its selected profile, verdict, and evidence bundle.</p></div>'
)


def build_html(document):
    """Derive the OriginScope-only UI without changing the reusable workbench on import."""
    document = document.replace("CVE report workbench", "OriginScope")
    document = document.replace(
        "Choose a complete image report or a scanner-finding review. OSIDB determines unresolved component status; provenance determines the RHEL release automatically from the input.",
        "Holistic image reporting for SBOMs and RPM inventories. OSIDB, public VEX, and BOMQ evidence determine component status and origin.",
    )
    document = document.replace(
        "</style>", "#analysis-mode{display:none!important;}#scanner-authority,#scanner-fields,#image-match{display:none!important;}</style>", 1
    )
    document = document.replace(
        "<h2 id=\"run-title\">Start an analysis</h2>", "<h2 id=\"run-title\">Analyze an image inventory</h2>",
    )
    document = document.replace(
        '<section class="authority"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section>',
        _assessment_profile_fields
        + '<section class="authority"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section>',
        1,
    )
    document = document.replace(
        '<a id="scanner-csv-link" href="#" hidden>Download scanner review CSV</a>',
        '<a id="scanner-csv-link" href="#" hidden>Download scanner review CSV</a>'
        '<a id="assessment-bundle-link" href="#" hidden>Download assessment evidence bundle</a>',
        1,
    )
    document = document.replace(
        '<div class="summary" id="summary" hidden></div></div><div id="results-empty"',
        '<div class="summary" id="summary" hidden></div><p class="hint" id="assessment-verdict" hidden></p></div><div id="results-empty"',
        1,
    )
    document = document.replace(
        "body:JSON.stringify({filename:file.name,analysisMode:mode(),imageReference:$('image-reference').value,architecture:$('architecture').value})",
        "body:JSON.stringify({filename:file.name,analysisMode:mode(),imageReference:$('image-reference').value,architecture:$('architecture').value,assessmentProfile:$('assessment-profile').value})",
        1,
    )
    document = document.replace(
        "$('scanner-csv-link').href=`${base}/scanner-csv`;",
        "$('scanner-csv-link').href=`${base}/scanner-csv`;$('assessment-bundle-link').href=`${base}/assessment-bundle`;",
        1,
    )
    document = document.replace(
        "||job.scannerEvidenceReady||job.scannerCsvReady);",
        "||job.scannerEvidenceReady||job.scannerCsvReady||job.assessmentBundleReady);",
        1,
    )
    document = document.replace(
        "async function showCompleted(job){",
        "async function renderAssessmentVerdict(job,base){const node=$('assessment-verdict');if(!job.assessmentBundleReady){node.hidden=true;return}try{const bundle=await api(`${base}/assessment-bundle`),policy=bundle.policy,profile=policy.profile;node.hidden=false;node.textContent=`Assessment: ${profile.name} v${profile.version} — ${policy.verdict.toUpperCase()}`}catch(error){node.hidden=false;node.textContent=`Assessment evidence could not be read: ${error.message}`}} async function showCompleted(job){",
        1,
    )
    document = document.replace(
        "if(job.resultsReady)await showCompleted(job)}",
        "await renderAssessmentVerdict(job,base);if(job.resultsReady)await showCompleted(job)}",
        1,
    )
    return document.replace(
        "$('scanner-csv-link').hidden=!job.scannerCsvReady;",
        "$('scanner-csv-link').hidden=!job.scannerCsvReady;$('assessment-bundle-link').hidden=!job.assessmentBundleReady;",
        1,
    )


def configure_workbench():
    workbench.ANALYSIS_MODES = {"holistic"}
    workbench.validate_options = validate_options
    workbench.APP_HTML = build_html(workbench.APP_HTML)


def main():
    parser = argparse.ArgumentParser(description="Run the OriginScope browser application.")
    parser.add_argument("--port", type=int, default=8765, help="Local port (default: 8765).")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    configure_workbench()
    server = workbench.ThreadingHTTPServer(("127.0.0.1", args.port), workbench.AppHandler)
    server.store = workbench.JobStore(args.data_dir, product_name="OriginScope")
    server.cache = workbench.VexCacheStore(workbench.VEX_CACHE_PATH, args.data_dir / "vex-cache.log")
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"OriginScope: {url}")
    print(f"Local run data: {args.data_dir}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OriginScope.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
