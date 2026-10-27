import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import cve_report_app
import scanner_csv
import vex_cache


class CveReportAppTests(unittest.TestCase):
    def test_safe_filename_cannot_escape_job_directory(self):
        self.assertEqual(cve_report_app.safe_filename("../../unsafe sbom.json"), "unsafe-sbom.json")
        self.assertEqual(cve_report_app.safe_filename("..."), "sbom.json")

    def test_validate_options_normalizes_ui_values(self):
        options = cve_report_app.validate_options({
            "filename": "image sbom.json",
            "source": "vex",
            "environment": "prod",
            "module": "rhel-10",
            "workers": "12",  # Browser input is intentionally ignored.
        })
        self.assertEqual(options["filename"], "image-sbom.json")
        self.assertEqual(options["workers"], cve_report_app.UI_WORKERS)
        self.assertNotIn("syncVex", options)
        self.assertEqual(options["architecture"], "amd64")
        self.assertEqual(options["analysisMode"], "holistic")
        self.assertEqual(options["assessmentProfile"], "report-only-v1")
        self.assertNotIn("module", options)
        self.assertNotIn("environment", options)

    def test_validate_options_accepts_only_known_assessment_profiles(self):
        options = cve_report_app.validate_options({
            "filename": "image.json",
            "assessmentProfile": "critical-exposure-gate-v1",
        })
        self.assertEqual(options["assessmentProfile"], "critical-exposure-gate-v1")
        with self.assertRaisesRegex(ValueError, "supported assessment profile"):
            cve_report_app.validate_options({"filename": "image.json", "assessmentProfile": "unknown"})

    def test_assessment_bundle_records_profile_policy_and_artifact_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = cve_report_app.JobStore(directory, product_name="OriginScope")
            job = store.create(cve_report_app.validate_options({
                "filename": "image.json",
                "assessmentProfile": "critical-exposure-gate-v1",
            }))
            job.input_path.write_text('{"components": []}\n', encoding="utf-8")
            job.report_path.write_text("# Report\n", encoding="utf-8")
            job.results_path.write_text(json.dumps({
                "summary": {"module": "rhel-10", "source": "OSIDB tracker"},
                "findings": [{
                    "cveId": "CVE-2026-00001", "impact": "CRITICAL", "remediationStatus": "unfixed",
                    "components": [{"originNvrs": ["openssl-3.0.0-1.el10"]}],
                }],
            }), encoding="utf-8")
            job.started_at = "2026-10-26T12:00:00+00:00"

            store._write_assessment_bundle(job, 0)
            bundle = json.loads(job.assessment_bundle_path.read_text(encoding="utf-8"))

        self.assertEqual(bundle["schema"], "originscope-assessment-bundle/v1")
        self.assertEqual(bundle["tool"]["name"], "OriginScope")
        self.assertEqual(bundle["profile"]["id"], "critical-exposure-gate-v1")
        self.assertEqual(bundle["policy"]["verdict"], "fail")
        self.assertIn("sha256", bundle["artifacts"]["input"])
        self.assertIn("bomqCache", bundle["evidence"])

    def test_completed_analysis_finalizes_a_read_only_assessment_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            store = cve_report_app.JobStore(directory, product_name="OriginScope")
            job = store.create(cve_report_app.validate_options({"filename": "image.json"}))
            job.input_path.write_text('{"components": []}\n', encoding="utf-8")
            job.status = "ready"

            def complete_checker(command, **_kwargs):
                results_path = Path(command[command.index("--report-json") + 1])
                results_path.write_text(json.dumps({"summary": {}, "findings": []}), encoding="utf-8")
                return type("Completed", (), {"returncode": 0})()

            with mock.patch.object(cve_report_app.subprocess, "run", side_effect=complete_checker):
                store._run(job)

            bundle = json.loads(job.assessment_bundle_path.read_text(encoding="utf-8"))
            self.assertEqual(job.status, "completed")
            self.assertEqual(bundle["policy"]["verdict"], "pass")
            self.assertEqual(job.assessment_bundle_path.stat().st_mode & 0o222, 0)

    def test_scanner_mode_accepts_structured_text_and_uses_osidb(self):
        options = cve_report_app.validate_options({
            "filename": "black-duck-findings.csv",
            "analysisMode": "scanner",
            "source": "osidb",
        })
        self.assertEqual(options["analysisMode"], "scanner")
        self.assertEqual(options["source"], "osidb")
        self.assertNotIn("syncVex", options)
        json_options = cve_report_app.validate_options({"filename": "scanner-results.json", "analysisMode": "scanner"})
        self.assertEqual(json_options["source"], "osidb")
        text_options = cve_report_app.validate_options({"filename": "grype-findings.out", "analysisMode": "scanner"})
        self.assertEqual(text_options["source"], "osidb")
        with self.assertRaisesRegex(ValueError, "requires a CSV, JSON, or supported text vulnerability report"):
            cve_report_app.validate_options({"filename": "image.xml", "analysisMode": "scanner"})
        with self.assertRaisesRegex(ValueError, "Scanner findings review"):
            cve_report_app.validate_options({"filename": "findings.csv"})

    def test_workbench_derives_bomq_streams_without_user_input(self):
        self.assertNotIn("bomqStream", cve_report_app.validate_options({"filename": "image.json"}))
        self.assertNotIn('id="bomq-stream"', cve_report_app.APP_HTML)
        self.assertIn('id="results-content"', cve_report_app.APP_HTML)
        self.assertNotIn('id="markdown-panel"', cve_report_app.APP_HTML)
        self.assertIn('id="previous-page"', cve_report_app.APP_HTML)
        self.assertIn('id="next-page"', cve_report_app.APP_HTML)
        self.assertIn('const PAGE_SIZE=10', cve_report_app.APP_HTML)
        self.assertIn('https://access.redhat.com/security/cve/', cve_report_app.APP_HTML)
        self.assertIn('<th>Advisory</th>', cve_report_app.APP_HTML)
        self.assertIn('<th>Upstream origin</th>', cve_report_app.APP_HTML)
        self.assertNotIn('<th>Scanner rationale</th>', cve_report_app.APP_HTML)
        self.assertNotIn('scannerRationale', cve_report_app.APP_HTML)
        self.assertNotIn('<th>Upstream local</th>', cve_report_app.APP_HTML)
        self.assertIn('value="unverified">Unverified', cve_report_app.APP_HTML)
        self.assertIn('only CVEs from the uploaded report', cve_report_app.APP_HTML)
        self.assertNotIn('<th>Image component</th>', cve_report_app.APP_HTML)
        self.assertNotIn('<th>Disposition</th>', cve_report_app.APP_HTML)
        self.assertNotIn('<th>Title</th>', cve_report_app.APP_HTML)
        self.assertIn('id="results-link"', cve_report_app.APP_HTML)
        self.assertIn('id="scanner-csv-link"', cve_report_app.APP_HTML)
        self.assertIn("$('vex-link').hidden=scanner||!job.vexReady", cve_report_app.APP_HTML)
        self.assertIn('id="scanner-fields"', cve_report_app.APP_HTML)
        self.assertIn('id="image-match"', cve_report_app.APP_HTML)
        self.assertIn('id="confirm-image"', cve_report_app.APP_HTML)
        self.assertIn('/image-candidates', cve_report_app.APP_HTML)
        self.assertIn('id="analysis-mode"', cve_report_app.APP_HTML)
        self.assertIn('id="analysis-settings-divider"', cve_report_app.APP_HTML)
        self.assertIn('id="scanner-authority"', cve_report_app.APP_HTML)
        self.assertIn('id="podman-status"', cve_report_app.APP_HTML)
        self.assertIn('/api/podman', cve_report_app.APP_HTML)
        self.assertNotIn('id="module"', cve_report_app.APP_HTML)
        self.assertNotIn('id="environment"', cve_report_app.APP_HTML)
        self.assertNotIn('id="workers"', cve_report_app.APP_HTML)
        self.assertNotIn("Parallel requests", cve_report_app.APP_HTML)
        self.assertNotIn('id="sync-vex"', cve_report_app.APP_HTML)
        self.assertNotIn('id="refresh-cache"', cve_report_app.APP_HTML)
        self.assertNotIn('id="rebuild-cache"', cve_report_app.APP_HTML)
        self.assertIn("OSIDB tracker status", cve_report_app.APP_HTML)

    def test_vex_cache_store_reports_missing_incomplete_and_ready_states(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "vex.sqlite3"
            store = cve_report_app.VexCacheStore(cache_path, Path(directory) / "vex-cache.log")
            self.assertEqual(store.snapshot()["state"], "missing")

            connection = vex_cache._connect(cache_path)
            connection.executemany("INSERT OR REPLACE INTO cache_metadata VALUES (?, ?)", [
                ("schema_version", "older"),
                ("build_state", "ready"),
            ])
            connection.commit()
            connection.close()
            self.assertEqual(store.snapshot()["state"], "outdated")

            connection = vex_cache._connect(cache_path)
            connection.executemany("INSERT OR REPLACE INTO cache_metadata VALUES (?, ?)", [
                ("scope", "global"),
                ("feed_url", vex_cache.VEX_BASE_URL),
                ("schema_version", vex_cache.CACHE_SCHEMA_VERSION),
                ("build_state", "building"),
            ])
            connection.execute("INSERT INTO documents(uri, modified) VALUES ('test.json', 'now')")
            connection.commit()
            connection.close()
            self.assertEqual(store.snapshot()["state"], "incomplete")

            connection = sqlite3.connect(cache_path)
            connection.execute("UPDATE cache_metadata SET value = 'ready' WHERE key = 'build_state'")
            connection.commit()
            connection.close()
            snapshot = store.snapshot()
            self.assertEqual(snapshot["state"], "ready")
            self.assertEqual(snapshot["documents"], 1)

            store.log_path.write_text("  VEX cache: indexed 1234/5678 documents\n")
            self.assertEqual(store.snapshot()["progress"], {"processed": 1234, "total": 5678})

    def test_scanner_image_requires_confirmation_after_candidate_match(self):
        with tempfile.TemporaryDirectory() as directory:
            store = cve_report_app.JobStore(directory)
            job = store.create(cve_report_app.validate_options({
                "filename": "openshift-gitops-operator-container_v1.21.5-4_grype.out",
                "analysisMode": "scanner",
            }))
            job.input_path.write_text(
                "NAME  INSTALLED  FIXED IN  TYPE  VULNERABILITY  SEVERITY\n"
                "curl  8.0        8.1       rpm   CVE-2026-00009  High\n", encoding="utf-8",
            )
            job.status = "ready"
            candidate = scanner_csv.ImageCandidate(
                "registry.access.redhat.com/openshift-gitops-1/gitops-rhel9-operator:v1.21.5-4",
                "openshift-gitops-1/gitops-rhel9-operator", "v1.21.5-4", "amd64",
                "openshift-gitops-operator-container", "openshift-gitops-operator-container-v1.21.5-4",
                "RHSA-2026:1", "https://catalog.example", 100, ("Brew build matches report name",),
            )
            with self.assertRaisesRegex(ValueError, "Confirm the Red Hat Catalog image"):
                store.start(job)
            with mock.patch.object(cve_report_app.scanner_csv, "suggest_image_candidates", return_value=[candidate]):
                matches = store.match_image(job)
            self.assertEqual(matches[0]["reference"], candidate.reference)
            snapshot = store.confirm_image(job, candidate.reference)
        self.assertTrue(snapshot["imageConfirmed"])
        self.assertEqual(snapshot["imageCandidates"][0]["score"], 100)

    def test_local_root_and_job_creation_api(self):
        with tempfile.TemporaryDirectory() as directory:
            server = ThreadingHTTPServer(("127.0.0.1", 0), cve_report_app.AppHandler)
            server.store = cve_report_app.JobStore(Path(directory))
            server.cache = cve_report_app.VexCacheStore(Path(directory) / "vex.sqlite3", Path(directory) / "vex-cache.log")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with urllib.request.urlopen(base_url + "/") as response:
                    self.assertIn(b"CVE report workbench", response.read())
                with urllib.request.urlopen(base_url + "/api/vex-cache") as response:
                    self.assertEqual(json.load(response)["state"], "missing")
                with mock.patch.object(cve_report_app.scanner_csv, "podman_status", return_value={
                    "available": False, "state": "unavailable", "message": "Podman is not running.",
                }):
                    with urllib.request.urlopen(base_url + "/api/podman") as response:
                        self.assertFalse(json.load(response)["available"])
                request = urllib.request.Request(
                    base_url + "/api/jobs",
                    data=json.dumps({"filename": "image.json"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request) as response:
                    job = json.load(response)
                self.assertRegex(job["id"], r"^[0-9a-f]{32}$")
                self.assertEqual(job["status"], "awaiting upload")
                stored_job = server.store.get(job["id"])
                self.assertEqual(stored_job.snapshot()["analysisMode"], "holistic")
                stored_job.report_path.write_text("# Completed analysis\n", encoding="utf-8")
                with urllib.request.urlopen(base_url + f"/api/jobs/{job['id']}/report") as response:
                    self.assertEqual(response.read(), b"# Completed analysis\n")
                stored_job.results_path.write_text('{"findings": []}\n', encoding="utf-8")
                with urllib.request.urlopen(base_url + f"/api/jobs/{job['id']}/results") as response:
                    self.assertEqual(json.load(response), {"findings": []})
                stored_job.catalog_sbom_path.write_text("{}\n", encoding="utf-8")
                with urllib.request.urlopen(base_url + f"/api/jobs/{job['id']}/catalog-sbom") as response:
                    self.assertEqual(response.read(), b"{}\n")
                stored_job.scanner_csv_path.write_text("CVE,Status\nCVE-2026-00001,fixed\n", encoding="utf-8")
                self.assertTrue(stored_job.snapshot()["scannerCsvReady"])
                with urllib.request.urlopen(base_url + f"/api/jobs/{job['id']}/scanner-csv") as response:
                    self.assertEqual(response.headers.get_content_type(), "text/csv")
                    self.assertEqual(response.read(), b"CVE,Status\nCVE-2026-00001,fixed\n")
                stored_job.assessment_bundle_path.write_text('{"policy": {"verdict": "pass"}}\n', encoding="utf-8")
                self.assertTrue(stored_job.snapshot()["assessmentBundleReady"])
                with urllib.request.urlopen(base_url + f"/api/jobs/{job['id']}/assessment-bundle") as response:
                    self.assertEqual(json.load(response)["policy"]["verdict"], "pass")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
