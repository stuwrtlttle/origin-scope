import tempfile
import unittest
from errno import EADDRINUSE
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cve_report_app
import vexscope_app


class VexScopeAppTests(unittest.TestCase):
    def test_vexscope_accepts_only_holistic_inventory_analysis(self):
        options = vexscope_app.validate_options({"filename": "image.sbom.json"})

        self.assertEqual(options["analysisMode"], "holistic")
        self.assertEqual(options["source"], "vex")
        with self.assertRaisesRegex(ValueError, "SBOM or RPM inventory"):
            vexscope_app.validate_options({"filename": "findings.csv", "analysisMode": "scanner"})

    def test_vexscope_validates_optional_immutable_pyxis_image_digest(self):
        digest = "sha256:" + "a" * 64
        options = vexscope_app.validate_options({
            "filename": "image.sbom.json",
            "pyxisImageReference": f"registry.redhat.io/example/image@{digest}",
            "pyxisArchitecture": "arm64",
        })

        self.assertEqual(options["pyxisImageReference"], f"registry.redhat.io/example/image@{digest}")
        self.assertEqual(options["pyxisArchitecture"], "arm64")
        with self.assertRaisesRegex(ValueError, "immutable image digest"):
            vexscope_app.validate_options({
                "filename": "image.sbom.json",
                "pyxisImageReference": "registry.redhat.io/example/image:latest",
            })

    def test_configure_workbench_installs_the_vex_only_server_configuration(self):
        original_html = cve_report_app.APP_HTML
        original_modes = cve_report_app.ANALYSIS_MODES
        original_validate = cve_report_app.validate_options
        try:
            vexscope_app.configure_workbench()
            self.assertEqual(cve_report_app.ANALYSIS_MODES, {"holistic"})
            self.assertIs(cve_report_app.validate_options, vexscope_app.validate_options)
            self.assertIn("VEXScope", cve_report_app.APP_HTML)
        finally:
            cve_report_app.APP_HTML = original_html
            cve_report_app.ANALYSIS_MODES = original_modes
            cve_report_app.validate_options = original_validate

    def test_default_port_falls_back_when_already_in_use(self):
        fallback_server = SimpleNamespace()
        address_in_use = OSError(EADDRINUSE, "Address already in use")
        with mock.patch.object(
            cve_report_app,
            "ThreadingHTTPServer",
            side_effect=[address_in_use, fallback_server],
        ) as server:
            self.assertIs(vexscope_app.create_server(vexscope_app.DEFAULT_PORT), fallback_server)

        self.assertEqual(server.call_args_list[0].args[0], ("127.0.0.1", vexscope_app.DEFAULT_PORT))
        self.assertEqual(server.call_args_list[1].args[0], ("127.0.0.1", 0))

    def test_requested_port_failure_is_reported(self):
        address_in_use = OSError(EADDRINUSE, "Address already in use")
        with mock.patch.object(cve_report_app, "ThreadingHTTPServer", side_effect=address_in_use):
            with self.assertRaises(OSError):
                vexscope_app.create_server(8767)

    def test_vexscope_ui_identifies_public_vex_and_exposes_cache_maintenance(self):
        html = vexscope_app.build_html(cve_report_app.APP_HTML)
        self.assertIn("VEXScope", html)
        self.assertIn("public Red Hat CSAF VEX feed", html)
        self.assertIn('id="refresh-vex-cache"', html)
        self.assertIn('id="rebuild-vex-cache"', html)
        self.assertIn("/api/vex-cache/", html)
        self.assertIn("if(!await requireVexCache())return", html)
        self.assertIn("scrollIntoView", html)
        self.assertIn("no BOMQ origin mapping is used", html)
        self.assertIn('id="pyxis-image-reference"', html)
        self.assertIn('id="pyxis-architecture"', html)
        self.assertIn('id="component-column">SBOM component', html)
        self.assertIn("Pyxis image-manifest", html)
        self.assertNotIn("$('run').disabled=!ready", html)
        self.assertNotIn("OSIDB tracker status", html)

    def test_vexscope_jobs_invoke_the_public_vex_cli_path(self):
        with tempfile.TemporaryDirectory() as directory:
            store = vexscope_app.create_store(directory)
            digest = "sha256:" + "a" * 64
            job = store.create(vexscope_app.validate_options({
                "filename": "image.sbom.json",
                "pyxisImageReference": f"registry.redhat.io/example/image@{digest}",
                "pyxisArchitecture": "arm64",
            }))
            job.input_path.write_text('{"components": []}\n', encoding="utf-8")
            job.status = "ready"
            with mock.patch.object(cve_report_app.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                store._run(job)

        command = run.call_args.args[0]
        self.assertEqual(store.source, "vex-direct")
        self.assertIn("--vex", command)
        self.assertIn("--vex-direct-components", command)
        self.assertIn("--pyxis-image", command)
        self.assertIn(f"registry.redhat.io/example/image@{digest}", command)
        self.assertIn("--pyxis-architecture", command)
        self.assertIn("arm64", command)
        self.assertIn("--report-json", command)
        self.assertIn("--vex-output", command)


if __name__ == "__main__":
    unittest.main()
