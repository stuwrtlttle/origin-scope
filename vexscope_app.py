#!/usr/bin/env python3
"""VEXScope: public Red Hat CSAF VEX-only image/SBOM reporting workbench."""

import argparse
import errno
from pathlib import Path
import webbrowser

import cve_report_app as workbench


def validate_options(payload):
    """Accept only holistic inventory analysis for the public-VEX workflow."""
    if not isinstance(payload, dict):
        raise ValueError("Configuration must be an object.")
    if payload.get("analysisMode") not in (None, "holistic"):
        raise ValueError("VEXScope accepts SBOM or RPM inventory analysis only.")
    pyxis_image = (payload.get("pyxisImageReference") or "").strip()
    pyxis_architecture = payload.get("pyxisArchitecture", "amd64")
    if pyxis_image:
        try:
            _, _, _, digest = workbench.scanner_csv.parse_image_reference(pyxis_image)
        except workbench.scanner_csv.ScannerInputError as exc:
            raise ValueError(str(exc)) from exc
        if not digest:
            raise ValueError("Use an immutable image digest (…@sha256:<digest>) for Pyxis mapping.")
    options = _base_validate({
        **payload, "analysisMode": "holistic", "architecture": pyxis_architecture,
    })
    options["source"] = "vex"
    options["pyxisImageReference"] = pyxis_image
    options["pyxisArchitecture"] = pyxis_architecture
    return options


def default_data_dir():
    return Path.home() / ".cache" / "vexscope"


def create_store(data_dir):
    return workbench.JobStore(data_dir, source="vex-direct", product_name="VEXScope")


_base_validate = workbench.validate_options
DEFAULT_PORT = 8766
_VEX_CACHE_SCRIPT = """
async function updateVexCacheStatus(){try{const cache=await api('/api/vex-cache'),busy=Boolean(cache.operation),ready=cache.state==='ready',progress=cache.progress?` · ${cache.progress.processed}/${cache.progress.total} indexed`:'';$('vex-cache-status').textContent=`${cache.message}${cache.documents==null?'':` · ${cache.documents} documents`}${progress}`;$('vex-cache-activity').textContent=cache.activity||'No cache activity yet.';$('refresh-vex-cache').disabled=busy;$('refresh-vex-cache').textContent=cache.state==='missing'||cache.state==='incomplete'?'Build cache':'Update cache';$('rebuild-vex-cache').disabled=busy;$('run').title=ready?'':'A VEX cache is required; click Run analysis for cache setup instructions.';return ready}catch(error){$('vex-cache-status').textContent=`Cache status could not be checked: ${error.message}`;return false}}
async function requireVexCache(){if(await updateVexCacheStatus())return true;const cacheConsole=$('vex-cache-status').closest('.cache-console');cacheConsole.scrollIntoView({behavior:'smooth',block:'center'});$('vex-cache-status').focus();setStatus('Build the public VEX cache using the controls at the top of this page before running an analysis.',true);return false}
async function maintainVexCache(operation){try{await api(`/api/vex-cache/${operation}`,{method:'POST'});await updateVexCacheStatus()}catch(error){setStatus(error.message,true)}}
$('refresh-vex-cache').addEventListener('click',()=>maintainVexCache('refresh'));
$('rebuild-vex-cache').addEventListener('click',()=>maintainVexCache('rebuild'));
updateVexCacheStatus();window.setInterval(updateVexCacheStatus,3000);
</script>"""


def build_html(html):
    """Derive the VEX-only UI without mutating the base app at import time."""
    html = html.replace("CVE report workbench", "VEXScope")
    html = html.replace(
        "Choose a complete image report or a scanner-finding review. OSIDB determines unresolved component status; provenance determines the RHEL release automatically from the input.",
        "Holistic image reporting from the public Red Hat CSAF VEX feed. By default, results use the component names and RPM builds supplied by the SBOM.",
    )
    html = html.replace(
        "</div></header>",
        """</div><section class="cache-console" aria-live="polite"><h2>Public VEX cache</h2><p class="cache-status" id="vex-cache-status" tabindex="-1">Checking local cache…</p><div class="cache-actions"><button id="refresh-vex-cache" type="button">Update cache</button><button id="rebuild-vex-cache" type="button">Rebuild cache</button></div><details><summary>Cache activity</summary><pre id="vex-cache-activity">No cache activity yet.</pre></details></section></header>""",
        1,
    )
    html = html.replace(
        "</style>",
        "#analysis-mode,#analysis-settings-divider{display:none!important;}#scanner-authority,#scanner-fields,#image-match{display:none!important;}</style>",
        1,
    )
    html = html.replace(
        '<section class="authority"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section>',
        '''<div class="fields" id="pyxis-fields"><label>Published image digest (optional)<input id="pyxis-image-reference" type="text" placeholder="registry.redhat.io/example/image@sha256:…"></label><label>Image architecture<select id="pyxis-architecture"><option value="amd64">x86_64 / amd64</option><option value="arm64">aarch64 / arm64</option><option value="ppc64le">ppc64le</option><option value="s390x">s390x</option></select></label><p class="hint">Use an immutable Red Hat registry digest to resolve the exact Pyxis RPM manifest and map matching SBOM RPMs to source RPMs. Unmatched packages remain SBOM identities; BOMQ is not used.</p></div><section class="authority"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section>''',
        1,
    )
    html = html.replace(
        "<h2 id=\"run-title\">Start an analysis</h2>",
        "<h2 id=\"run-title\">Analyze an image inventory</h2>",
    )
    html = html.replace(
        "Assess every component in an SBOM or RPM manifest, then produce a full report and local CSAF VEX.",
        "Assess every component in an SBOM or RPM manifest against public Red Hat CSAF VEX data.",
    )
    html = html.replace(
        "<section class=\"authority\"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section>",
        "<section class=\"authority\"><strong>Analysis uses public Red Hat CSAF VEX data.</strong> Results match the SBOM-supplied RPM component name and build directly unless an optional Pyxis image digest maps an exact package to its source RPM; no BOMQ origin mapping is used. Absent VEX coverage remains explicit.</section>",
    )
    html = html.replace(
        "'Assess every component in an SBOM or RPM manifest against OSIDB tracker status; RHEL release is inferred from component provenance.'",
        "'Assess every component in an SBOM or RPM manifest against public Red Hat CSAF VEX data using the component names and RPM builds supplied by the SBOM.'",
    )
    html = html.replace(
        "`${s.unfixedCves??s.unresolvedCves} unfixed · ${s.fixedCves??0} fixed · ${s.unverifiedCves??0} unverified · ${s.componentsScanned} components · ${s.module} · ${s.source}`",
        "`${s.unresolvedCves??0} reported · ${s.vexCoverageGaps??0} coverage gaps · ${s.componentsScanned} components · ${s.module} · ${s.source}`",
    )
    html = html.replace(
        "<th>Origin component</th><th>Upstream origin</th>",
        "<th id=\"component-column\">SBOM component</th><th id=\"build-column\">SBOM package build</th>",
    )
    html = html.replace(
        "function componentText(row,key,fallback='not found'){return row.components.flatMap(c=>c[key]||[]).filter(Boolean).join(', ')||fallback}",
        "function componentText(row,key,fallback='not found'){return row.components.flatMap(c=>c[key]||[]).filter(Boolean).join(', ')||fallback} function componentName(row){return row.components.map(c=>c.originComponent).filter(Boolean).join(', ')||'not found'}",
    )
    html = html.replace(
        "componentText(row,'imageComponents'),componentText(row,'originNvrs'),componentText(row,'upstreamStreams')",
        "componentName(row),componentText(row,'originNvrs'),componentText(row,'upstreamStreams')",
    )
    html = html.replace(
        "componentText(row,'originNvrs'),componentText(row,'upstreamStreams')",
        "componentName(row),componentText(row,'originNvrs')",
    )
    html = html.replace(
        "cell(row,componentText(item,'originNvrs'));cell(row,componentText(item,'upstreamStreams'));",
        "cell(row,componentName(item));cell(row,componentText(item,'originNvrs'));",
    )
    html = html.replace(
        "function renderResults(data){resultData=data;currentPage=1;const s=data.summary;",
        "function renderResults(data){resultData=data;currentPage=1;const s=data.summary,pyxis=s.source.includes('Pyxis image-manifest');$('component-column').textContent=pyxis?'Pyxis source component / SBOM fallback':'SBOM component';$('build-column').textContent=pyxis?'Mapped RPM build':'SBOM package build';",
    )
    html = html.replace(
        "$('run-form').addEventListener('submit',async event=>{event.preventDefault();const file=fileInput.files[0],scanner=mode()==='scanner';",
        "$('run-form').addEventListener('submit',async event=>{event.preventDefault();if(!await requireVexCache())return;const file=fileInput.files[0],scanner=mode()==='scanner';",
    )
    html = html.replace(
        "body:JSON.stringify({filename:file.name,analysisMode:mode(),imageReference:$('image-reference').value,architecture:$('architecture').value})",
        "body:JSON.stringify({filename:file.name,analysisMode:mode(),pyxisImageReference:$('pyxis-image-reference').value,pyxisArchitecture:$('pyxis-architecture').value})",
    )
    html = html.replace("OSIDB tracker status", "public Red Hat CSAF VEX data")
    return html.replace("</script>", _VEX_CACHE_SCRIPT, 1)


def configure_workbench():
    """Install VEXScope configuration immediately before serving it."""
    workbench.ANALYSIS_MODES = {"holistic"}
    workbench.validate_options = validate_options
    workbench.APP_HTML = build_html(workbench.APP_HTML)


def create_server(port):
    """Bind the requested localhost port, falling back from the default only."""
    try:
        return workbench.ThreadingHTTPServer(("127.0.0.1", port), workbench.AppHandler)
    except OSError as exc:
        if port != DEFAULT_PORT or exc.errno != errno.EADDRINUSE:
            raise
        print(f"Port {DEFAULT_PORT} is already in use; selecting an available local port.")
        return workbench.ThreadingHTTPServer(("127.0.0.1", 0), workbench.AppHandler)


def main():
    parser = argparse.ArgumentParser(description="Run the VEXScope browser application.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Local port (default: 8766).")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    configure_workbench()
    server = create_server(args.port)
    server.store = create_store(args.data_dir)
    server.cache = workbench.VexCacheStore(workbench.VEX_CACHE_PATH, args.data_dir / "vex-cache.log")
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"VEXScope: {url}")
    print(f"Local run data: {args.data_dir}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping VEXScope.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
