import contextlib
import json
import io
import os
import sys
import tempfile
import urllib.error
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import vex_cache
import cve_report


def compare_evr(left, right):
    """Enough ordering for the fixed-build precedence cases in this test."""
    return (left > right) - (left < right)


class VexFindingsTests(unittest.TestCase):
    def setUp(self):
        handle, self.cache_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(handle)
        self.connection = vex_cache._connect(self.cache_path)
        self.connection.executemany("INSERT INTO cache_metadata VALUES (?, ?)", [
            ("scope", "global"),
            ("feed_url", vex_cache.VEX_BASE_URL),
            ("build_state", "ready"),
            ("schema_version", vex_cache.CACHE_SCHEMA_VERSION),
        ])
        self.connection.commit()

    def tearDown(self):
        self.connection.close()
        os.unlink(self.cache_path)

    def add_rows(self, rows):
        self.connection.execute(
            "INSERT OR IGNORE INTO documents(uri, modified) VALUES (?, ?)", ("test.json", "now")
        )
        self.connection.executemany(
            "INSERT INTO rpm_status(uri, cve_id, component, evr, stream, status, title, impact, cvss) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows,
        )
        self.connection.commit()

    def test_canonical_uri_normalizes_case_only_cve_paths(self):
        self.assertEqual(vex_cache._canonical_uri("2026/CVE-2026-3099.json"),
                         "2026/cve-2026-3099.json")
        self.assertEqual(vex_cache._canonical_uri("./vex-feed/2026/cve-2026-3099.json"),
                         "2026/cve-2026-3099.json")

    def test_canonical_cve_id_excludes_osidb_uuid_values(self):
        self.assertEqual(cve_report.canonical_cve_id("cve-2026-12345"), "CVE-2026-12345")
        self.assertIsNone(cve_report.canonical_cve_id("a65bd85f-c2ce-447c-a44c-324f7efec3c6"))

    def test_cve_filter_accepts_only_public_cve_ids(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as handle:
            handle.write("cve-2026-00001\nnot-a-cve\nCVE-2026-00002\n")
            path = handle.name
        try:
            self.assertEqual(cve_report.load_cve_filter(path), {
                "CVE-2026-00001", "CVE-2026-00002",
            })
        finally:
            os.unlink(path)

    def test_scanner_component_filter_maps_binary_packages_to_source_components(self):
        selected = cve_report.select_scanner_components(
            {"curl", "openssl"},
            {
                "curl": {"libcurl-8.0-1.el9.x86_64"},
                "openssl": {"openssl-libs-3.0-1.el9.x86_64"},
            },
            {"libcurl"},
        )
        self.assertEqual(selected, {"curl"})

    def test_fixed_exact_build_overrides_generic_affected_state(self):
        self.add_rows([
            ("test.json", "CVE-TEST-1", "openssl", "0:3.0-2.el10_2", "10.2", "fixed", "", "", None),
            ("test.json", "CVE-TEST-1", "openssl", "", "10.0", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"openssl": {"openssl-0:3.0-3.el10_2"}},
            "rhel-10",
            compare_evr,
        )

        self.assertEqual(findings, [])
        self.assertEqual(unknown, [])

    def test_safe_state_for_one_cve_does_not_hide_another_cve(self):
        self.add_rows([
            ("test.json", "CVE-TEST-SAFE", "curl", "", "10.2", "known_not_affected", "", "", None),
            ("test.json", "CVE-TEST-AFFECTED", "curl", "", "10.2", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"curl": {"curl-0:8.0-1.el10_2"}},
            "rhel-10",
            compare_evr,
        )

        self.assertEqual([finding["cve_id"] for finding in findings], ["CVE-TEST-AFFECTED"])
        self.assertEqual(unknown, [])

    def test_exact_safe_state_for_one_cve_does_not_hide_generic_affected_cve(self):
        self.add_rows([
            ("test.json", "CVE-TEST-SAFE", "openssl", "0:3.0-2.el10_2", "10.2", "fixed", "", "", None),
            ("test.json", "CVE-TEST-AFFECTED", "openssl", "", "10.2", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"openssl": {"openssl-0:3.0-3.el10_2"}},
            "rhel-10",
            compare_evr,
        )

        self.assertEqual([finding["cve_id"] for finding in findings], ["CVE-TEST-AFFECTED"])
        self.assertEqual(unknown, [])

    def test_generic_major_state_applies_to_a_matching_minor(self):
        self.add_rows([
            ("test.json", "CVE-TEST-2", "rpm", "", "10.0", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"rpm": {"rpm-0:4.20-1.el10_2"}},
            "rhel-10",
            compare_evr,
        )

        self.assertEqual([finding["cve_id"] for finding in findings], ["CVE-TEST-2"])
        self.assertEqual(unknown, [])

    def test_bomq_stream_overrides_a_major_only_rpm_release(self):
        self.add_rows([
            ("test.json", "CVE-TEST-STREAM", "gcc", "", "10.0", "known_affected", "", "", None),
            ("test.json", "CVE-TEST-STREAM", "gcc", "", "10.2", "known_not_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"gcc": {"gcc-14.3.1-4.4.el10"}},
            "rhel-10",
            compare_evr,
            upstream_origins={("gcc", "gcc-14.3.1-4.4.el10"): {"rhel-10.2.z"}},
        )

        self.assertEqual(findings, [])
        self.assertEqual(unknown, [])

    def test_ambiguous_bomq_streams_are_a_coverage_gap(self):
        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"gcc": {"gcc-14.3.1-4.4.el10"}},
            "rhel-10",
            compare_evr,
            upstream_origins={("gcc", "gcc-14.3.1-4.4.el10"): {"rhel-10.2.z", "rhel-10.3.z"}},
        )

        self.assertEqual(findings, [])
        self.assertEqual(unknown[0][2], "BOMQ provenance identifies multiple upstream streams")

    def test_dominant_image_stream_resolves_an_inherited_source_build(self):
        self.add_rows([
            ("test.json", "CVE-TEST-INHERITED", "bluez", "", "10.2", "known_affected", "", "", None),
            ("test.json", "CVE-TEST-INHERITED", "bluez", "", "10.3", "known_not_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"bluez": {"bluez-5.85-1.el10"}},
            "rhel-10",
            compare_evr,
            upstream_origins={
                ("bluez", "bluez-5.85-1.el10"): {"rhel-10.2.z", "rhel-10.3.z"},
                ("anchor", "anchor-1-1.el10_2"): {"rhel-10.2.z"},
            },
        )

        self.assertEqual([finding["cve_id"] for finding in findings], ["CVE-TEST-INHERITED"])
        self.assertEqual(unknown, [])

    def test_binary_alias_is_used_for_a_renamed_source_rpm(self):
        self.add_rows([
            ("test.json", "CVE-TEST-ALIASED", "rpm-sequoia", "", "10.0", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"rust-rpm-sequoia": {"rust-rpm-sequoia-0:1.0-1.el10_2"}},
            "rhel-10",
            compare_evr,
            component_origins={"rust-rpm-sequoia": {"rpm-sequoia-1.10.2.1"}},
        )

        self.assertEqual([finding["cve_id"] for finding in findings], ["CVE-TEST-ALIASED"])
        self.assertEqual(unknown, [])

    def test_vexscope_and_origin_scope_use_intentionally_different_component_identity(self):
        """VEXScope is direct; OriginScope retains source-RPM/BOMQ matching."""
        self.add_rows([
            ("test.json", "CVE-2026-12345", "libcurl", "", "10.2", "known_affected",
             "", "IMPORTANT", 7.5),
        ])
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [{
                "type": "library",
                "name": "libcurl",
                "version": "0:8.0-1.el10_2",
                "purl": "pkg:rpm/redhat/libcurl@0:8.0-1.el10_2?arch=x86_64",
                "properties": [
                    {"name": "redhat:catalog-source-name", "value": "curl"},
                    {"name": "redhat:catalog-source-nvr", "value": "curl-0:8.0-1.el10_2"},
                ],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_path = directory / "image.cdx.json"
            vex_results = directory / "vex-results.json"
            origin_results = directory / "origin-results.json"
            input_path.write_text(json.dumps(sbom), encoding="utf-8")

            direct_stdout = io.StringIO()
            direct_stderr = io.StringIO()
            with patch("cve_report.bomq_origin_streams", side_effect=AssertionError("BOMQ must not run")) as bomq, \
                 patch.object(sys, "argv", [
                     "cve_report.py", str(input_path), "--vex", "--vex-direct-components",
                     "--vex-cache", self.cache_path, "--report-json", str(vex_results), "--no-vex-output",
                 ]), \
                 contextlib.redirect_stdout(direct_stdout), contextlib.redirect_stderr(direct_stderr):
                cve_report.main()

            vex_report = json.loads(vex_results.read_text(encoding="utf-8"))
            vex_component = vex_report["findings"][0]["components"][0]
            self.assertEqual(vex_component["originComponent"], "libcurl")
            self.assertEqual(vex_component["originNvrs"], ["libcurl-0:8.0-1.el10_2"])
            self.assertEqual(vex_component["upstreamStreams"], [])
            self.assertIn("direct SBOM component match", vex_report["summary"]["source"])
            self.assertIn("SBOM component | Component NVR", direct_stdout.getvalue())
            self.assertNotIn("Resolving BOMQ", direct_stderr.getvalue())
            bomq.assert_not_called()

            origin_stdout = io.StringIO()
            with patch("cve_report.resolve_bomq_origin_streams", return_value={
                ("curl", "curl-0:8.0-1.el10_2"): {"rhel-10.2.z"},
            }) as resolve_bomq, \
                 patch("cve_report.get_affects_for_component", return_value=[{
                     "uuid": "affect-1", "flaw": "flaw-1", "ps_component": "curl",
                     "affectedness": "AFFECTED", "resolution": "NEW", "impact": "IMPORTANT",
                 }]), \
                 patch("cve_report.get_flaw_details", return_value={"flaw-1": {
                     "cve_id": "CVE-2026-12345", "impact": "IMPORTANT", "title": "curl test",
                     "cvss_scores": [],
                 }}), \
                 patch("cve_report.fetch_security_data", return_value={}), \
                 patch.object(sys, "argv", [
                     "cve_report.py", str(input_path), "--report-json", str(origin_results), "--no-vex-output",
                     "--vex-cache", self.cache_path,
                 ]), \
                 contextlib.redirect_stdout(origin_stdout), contextlib.redirect_stderr(io.StringIO()):
                cve_report.main()

            origin_report = json.loads(origin_results.read_text(encoding="utf-8"))
            origin_component = origin_report["findings"][0]["components"][0]
            self.assertEqual(origin_component["originComponent"], "curl")
            self.assertEqual(origin_component["originNvrs"], ["curl-0:8.0-1.el10_2"])
            self.assertEqual(origin_component["upstreamStreams"], ["rhel-10.2.z"])
            self.assertEqual(origin_report["summary"]["source"], "OSIDB tracker")
            self.assertEqual(origin_report["findings"][0]["remediationStatus"], "unfixed")
            self.assertIn("Origin component (source NVR) | Upstream local", origin_stdout.getvalue())
            resolve_bomq.assert_called_once()

    def test_pyxis_manifest_maps_exact_sbom_rpms_to_source_without_bomq(self):
        """An immutable image manifest is source identity, not BOMQ provenance."""
        self.add_rows([
            ("test.json", "CVE-2026-54321", "curl", "", "10.2", "known_affected",
             "", "IMPORTANT", 7.5),
        ])
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [{
                "type": "library", "name": "libcurl", "version": "0:8.0-1.el10_2",
                "purl": "pkg:rpm/redhat/libcurl@0:8.0-1.el10_2?arch=x86_64",
            }],
        }
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_path = directory / "image.cdx.json"
            results_path = directory / "results.json"
            input_path.write_text(json.dumps(sbom), encoding="utf-8")
            subject = SimpleNamespace(
                resolved_reference=f"registry.redhat.io/example/image@{digest}",
            )
            manifest = [{
                "name": "libcurl", "nvra": "libcurl-8.0-1.el10_2.x86_64",
                "srpm_name": "curl", "srpm_nevra": "curl-0:8.0-1.el10.src",
            }]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch.object(cve_report.scanner_csv, "resolve_redhat_image", return_value=subject) as resolve, \
                 patch.object(cve_report.scanner_csv, "fetch_rpm_manifest", return_value=manifest) as fetch, \
                 patch("cve_report.bomq_origin_streams", side_effect=AssertionError("BOMQ must not run")) as bomq, \
                 patch.object(sys, "argv", [
                     "cve_report.py", str(input_path), "--vex", "--vex-direct-components",
                     "--pyxis-image", f"registry.redhat.io/example/image@{digest}",
                     "--vex-cache", self.cache_path, "--report-json", str(results_path), "--no-vex-output",
                 ]), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                cve_report.main()
            report = json.loads(results_path.read_text(encoding="utf-8"))
            component = report["findings"][0]["components"][0]
            self.assertEqual(component["originComponent"], "curl")
            self.assertEqual(component["originNvrs"], ["curl-0:8.0-1.el10"])
            self.assertEqual(component["imageComponents"], ["libcurl-0:8.0-1.el10_2"])
            self.assertIn("Pyxis image-manifest source mapping", report["summary"]["source"])
            self.assertIn("Pyxis source component (SBOM fallback)", stdout.getvalue())
            self.assertIn("Pyxis source-RPM mapping: 1 exact SBOM RPM(s), 0 SBOM fallback(s)", stderr.getvalue())
            self.assertNotIn("Resolving BOMQ", stderr.getvalue())
            resolve.assert_called_once_with(f"registry.redhat.io/example/image@{digest}", "amd64")
            fetch.assert_called_once_with(subject)
            bomq.assert_not_called()

    def test_newer_stream_state_does_not_apply_to_an_older_image(self):
        self.add_rows([
            ("test.json", "CVE-TEST-3", "curl", "0:8.0-1.el10_3", "10.3", "known_affected", "", "", None),
        ])

        findings, unknown = vex_cache.findings(
            self.cache_path,
            {"curl": {"curl-0:8.0-1.el10_2"}},
            "rhel-10",
            compare_evr,
        )

        self.assertEqual(findings, [])
        self.assertEqual(unknown[0][:2], ("curl", "curl-0:8.0-1.el10_2"))

    def test_manifest_provenance_and_vex_report_columns(self):
        _, _, _, origins = cve_report.parse_rpm_manifest([
            "libcurl|0|8.0-1.el10_2|x86_64|curl-8.0-1.el10_2.src.rpm\n",
        ])
        self.assertEqual(origins["curl"], {"libcurl-8.0-1.el10_2"})

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cve_report.finish_report(
                "image-rpms.tsv", "rhel-10", 1,
                [{"cve_id": "CVE-TEST-4", "impact": "IMPORTANT", "cvss": 7.5,
                  "title": "example", "component": "curl", "origin_component": "curl",
                  "origin_nvrs": ["curl-8.0-1.el10_2"],
                  "upstream_streams": ["rhel-10.2.z"],
                  "image_components": ["libcurl-8.0-1.el10_2"], "resolution": "known_affected",
                  "workflow_state": "PUBLIC VEX"}],
                source="Public Red Hat CSAF VEX",
            )

        report = output.getvalue()
        self.assertIn("VEX status", report)
        self.assertIn("Image component (NVR)", report)
        self.assertIn("Upstream local", report)
        self.assertIn("known_affected | — | libcurl-8.0-1.el10_2 | curl-8.0-1.el10_2 | rhel-10.2.z", report)

    def test_structured_report_preserves_the_markdown_finding_provenance(self):
        affect = {"cve_id": "CVE-TEST-STRUCTURED", "impact": "IMPORTANT", "cvss": 7.5,
                  "title": "example", "component": "curl", "origin_component": "curl",
                  "origin_nvrs": ["curl-8.0-1.el10_2"],
                  "upstream_streams": ["rhel-10.2.z"],
                  "image_components": ["libcurl-8.0-1.el10_2"],
                  "resolution": "known_affected"}
        deduped, groups, info = cve_report.prepare_report([affect])

        report = cve_report.structured_report(
            "image.sbom.json", "rhel-10", 1, deduped, groups, info,
            source="Public Red Hat CSAF VEX",
        )

        self.assertEqual(report["summary"]["module"], "rhel-10")
        self.assertEqual(report["findings"][0]["status"], ["known_affected"])
        self.assertIsNone(report["findings"][0]["remediationStatus"])
        self.assertEqual(report["findings"][0]["advisories"], [])
        self.assertEqual(report["findings"][0]["components"][0]["imageComponents"],
                         ["libcurl-8.0-1.el10_2"])
        self.assertEqual(report["findings"][0]["components"][0]["upstreamStreams"],
                         ["rhel-10.2.z"])

    def test_rhel9_fixed_build_status_includes_the_advisory(self):
        security_data = {"affected_release": [{
            "product_name": "Red Hat Enterprise Linux 9",
            "package": "curl-0:8.0-1.el9_4",
            "cpe": "cpe:/o:redhat:enterprise_linux:9.4",
            "advisory": "RHSA-2026:81522",
        }]}

        fixed, _, advisories = cve_report.component_status_from_security_data(
            security_data, "rhel-9", "curl", {"curl-0:8.0-2.el9_4"},
        )

        self.assertTrue(fixed)
        self.assertEqual(advisories, {"RHSA-2026:81522"})

    def test_non_object_security_data_does_not_abort_reconciliation(self):
        fixed, reason, advisories = cve_report.component_status_from_security_data(
            "unexpected public security-data response", "rhel-9", "curl", {"curl-0:8.0-2.el9_4"},
        )

        self.assertFalse(fixed)
        self.assertEqual(reason, "no public Red Hat fixed-build data")
        self.assertEqual(advisories, set())

    def test_delegated_terminal_affects_have_explicit_origin_statuses(self):
        self.assertEqual(cve_report.origin_affect_status({
            "affectedness": "DELEGATED", "resolution": "Done",
        }), "fixed")
        self.assertEqual(cve_report.origin_affect_status({
            "affectedness": "DELEGATED", "resolution": "Not a Bug",
        }), "not a bug")
        self.assertIsNone(cve_report.origin_affect_status({
            "affectedness": "AFFECTED", "resolution": "FIX",
        }))
        self.assertEqual(cve_report.origin_affect_status({
            "uuid": "affect-1", "affectedness": "DELEGATED", "resolution": "DELEGATED",
            "trackers": [{"affects": ["affect-1"], "resolution": "Done"}],
        }), "fixed")

    def test_vex_fixed_status_reconciles_an_osidb_candidate(self):
        self.add_rows([
            ("test.json", "CVE-TEST-FIXED", "curl", "0:8.0-1.el9_4", "9.4", "fixed", "", "", None),
        ])

        statuses = vex_cache.fixed_component_statuses(
            self.cache_path,
            {"curl": {"curl-0:8.0-2.el9_4"}},
            {("CVE-TEST-FIXED", "curl")},
            "rhel-9",
            compare_evr,
        )

        self.assertEqual(statuses, {("CVE-TEST-FIXED", "curl"): "fixed"})

    @patch("cve_report.fetch_bomq_json")
    def test_bomq_origin_uses_the_image_minor_and_exact_source_nvr(self, fetch_bomq_json):
        fetch_bomq_json.return_value = {"data": [
            {"stream_name": "rhel-10.2.z", "build_type": "rpm",
             "purl": "pkg:rpm/redhat/curl@8.0-1.el10_2?arch=src"},
            {"stream_name": "rhel-10.2.z", "build_type": "rpm",
             "purl": "pkg:rpm/redhat/curl@8.0-2.el10_2?arch=src"},
        ]}

        streams = cve_report.bomq_origin_streams("rhel-10", "curl", "curl-8.0-1.el10_2")

        self.assertEqual(streams, {"rhel-10.2.z"})
        self.assertIn("include_streams=rhel-10.2%2A", fetch_bomq_json.call_args.args[0])

    @patch("cve_report.bomq_origin_streams")
    def test_bomq_origins_are_available_to_osidb_reports(self, bomq_origin_streams):
        bomq_origin_streams.return_value = {"rhel-10.2.z"}
        cache_path = f"{self.cache_path}.bomq.json"

        origins = cve_report.resolve_bomq_origin_streams(
            "rhel-10", {"curl": {"curl-8.0-1.el10_2"}}, cache_path,
        )

        self.assertEqual(origins[("curl", "curl-8.0-1.el10_2")], {"rhel-10.2.z"})
        self.assertTrue(Path(cache_path).is_file())
        Path(cache_path).unlink()

    def test_bomq_cache_round_trip_retains_empty_and_populated_streams(self):
        cache_path = f"{self.cache_path}.bomq.json"
        entries = {}
        cve_report.cache_bomq_origin_streams(entries, "rhel-10", "curl", "curl-8.0-1.el10_2", {"rhel-10.2.z"})
        cve_report.cache_bomq_origin_streams(entries, "rhel-10", "opus", "opus-1.4-6.el10", set())
        cve_report.save_bomq_cache(cache_path, entries)

        loaded = cve_report.load_bomq_cache(cache_path)

        self.assertEqual(cve_report.cached_bomq_origin_streams(loaded, "rhel-10", "curl", "curl-8.0-1.el10_2"),
                         {"rhel-10.2.z"})
        self.assertEqual(cve_report.cached_bomq_origin_streams(loaded, "rhel-10", "opus", "opus-1.4-6.el10"), set())

    def test_compact_cache_deduplicates_equivalent_product_statuses(self):
        row = ("test.json", "CVE-TEST-DEDUP", "curl", "0:8.0-1.el10_2", "10.2", "known_affected", "", "", None)
        self.connection.executemany(
            "INSERT OR IGNORE INTO rpm_status(uri, cve_id, component, evr, stream, status, title, impact, cvss) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [row, row],
        )
        self.connection.commit()
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM rpm_status").fetchone()[0], 1)

    def test_vex_normalization_is_scoped_to_the_requested_rhel_major(self):
        document = {
            "product_tree": {"branches": [{"product": {
                "product_id": "BaseOS-10.2.Z",
                "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:10.2"},
            }}]},
            "vulnerabilities": [{"cve": "CVE-TEST-5", "product_status": {
                "known_affected": ["BaseOS-10.2.Z:curl-0:8.0-1.el10_2.x86_64"],
            }}],
        }

        _, _, rhel10_rows = vex_cache._normalized_rows("test.json", document, "rhel-10")
        _, _, rhel9_rows = vex_cache._normalized_rows("test.json", document, "rhel-9")

        self.assertEqual(len(rhel10_rows), 1)
        self.assertEqual(rhel10_rows[0][2:6], ("curl", "0:8.0-1.el10_2", "10.2", "known_affected"))
        self.assertEqual(rhel9_rows, [])

    def test_vex_normalization_keeps_eus_affected_status_and_disposition(self):
        document = {
            "product_tree": {"branches": [{"product": {
                "product_id": "rhel-10.0.z.eus",
                "product_identification_helper": {},
            }}]},
            "vulnerabilities": [{
                "cve": "CVE-TEST-DEFER",
                "product_status": {"known_affected": ["rhel-10.0.z.eus:slf4j.src"]},
                "remediations": [{
                    "category": "none_available", "details": "Affected",
                    "product_ids": ["rhel-10.0.z.eus:slf4j.src"],
                }],
            }],
        }

        _, _, rows = vex_cache._normalized_rows("test.json", document, "rhel-10")

        self.assertEqual(rows[0][2:7], (
            "slf4j", "", "10.0", "known_affected", "deferred / no fix available",
        ))

    @patch("vex_cache.zstd", None)
    @patch("vex_cache._request")
    def test_sync_fetches_only_documents_with_newer_feed_timestamps(self, request):
        changes = "example.json,2026-10-18T00:00:00Z\n"
        request.side_effect = [changes, "{}"]

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 1)
        self.assertEqual(request.call_count, 2)

        request.reset_mock()
        request.side_effect = None
        request.return_value = changes
        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 0)
        request.assert_called_once_with(vex_cache.VEX_BASE_URL + "changes.csv", "text/csv")
        last_sync = self.connection.execute(
            "SELECT value FROM cache_metadata WHERE key = 'last_sync_at'"
        ).fetchone()
        self.assertIsNotNone(last_sync)

    @patch("vex_cache._request")
    def test_update_migrates_schema_three_without_rebuilding_documents(self, request):
        self.connection.execute("DROP TABLE rpm_status")
        self.connection.executescript("""
            CREATE TABLE rpm_status (
                uri TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                component TEXT NOT NULL,
                evr TEXT NOT NULL DEFAULT '',
                stream TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                title TEXT,
                impact TEXT,
                cvss REAL,
                PRIMARY KEY (uri, cve_id, component, evr, stream, status)
            ) WITHOUT ROWID;
        """)
        self.connection.execute("UPDATE cache_metadata SET value = '3' WHERE key = 'schema_version'")
        self.connection.execute("INSERT INTO documents(uri, modified) VALUES ('unchanged.json', 'now')")
        self.connection.commit()
        request.return_value = "unchanged.json,now\n"

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 0)

        self.assertEqual(self.connection.execute(
            "SELECT value FROM cache_metadata WHERE key = 'schema_version'"
        ).fetchone(), (vex_cache.CACHE_SCHEMA_VERSION,))
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM documents").fetchone(), (1,))
        self.assertIn("disposition", {row[1] for row in self.connection.execute("PRAGMA table_info(rpm_status)")})

    @patch("vex_cache.zstd", None)
    @patch("vex_cache._request")
    def test_update_replaces_case_variant_false_404_with_canonical_document(self, request):
        self.connection.execute(
            "INSERT INTO unavailable_documents(uri, modified, reason) VALUES (?, ?, ?)",
            ("2026/CVE-2026-3099.json", "old", "HTTP 404"),
        )
        self.connection.commit()
        request.side_effect = [
            "2026/cve-2026-3099.json,new\n",
            json.dumps({"vulnerabilities": []}),
        ]

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 1)
        self.assertEqual(self.connection.execute(
            "SELECT COUNT(*) FROM unavailable_documents"
        ).fetchone(), (0,))
        self.assertEqual(self.connection.execute(
            "SELECT uri FROM documents"
        ).fetchone(), ("2026/cve-2026-3099.json",))

    @patch("vex_cache.zstd", None)
    @patch("vex_cache._request")
    def test_sync_remembers_withdrawn_feed_documents(self, request):
        changes = "withdrawn.json,2026-10-18T00:00:00Z\n"
        request.side_effect = [
            changes,
            urllib.error.HTTPError("https://example.test/withdrawn.json", 404, "Not Found", None, None),
        ]

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 1)
        self.assertEqual(self.connection.execute(
            "SELECT uri, modified, reason FROM unavailable_documents"
        ).fetchone(), ("withdrawn.json", "2026-10-18T00:00:00Z", "HTTP 404"))

        request.reset_mock()
        request.side_effect = None
        request.return_value = changes
        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 0)
        request.assert_called_once_with(vex_cache.VEX_BASE_URL + "changes.csv", "text/csv")

    @patch("vex_cache.time.sleep")
    @patch("vex_cache.zstd", None)
    @patch("vex_cache._request")
    def test_sync_retries_transient_document_failure(self, request, sleep):
        changes = "example.json,2026-10-18T00:00:00Z\n"
        request.side_effect = [
            changes,
            urllib.error.HTTPError("https://example.test/example.json", 503, "Unavailable", None, None),
            "{}",
        ]

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 1)
        self.assertEqual(request.call_count, 3)
        sleep.assert_called_once_with(0.5)

    @patch("vex_cache.zstd", None)
    @patch("vex_cache._request")
    def test_incomplete_cache_resumes_when_a_document_timestamp_changed(self, request):
        self.connection.execute(
            "INSERT INTO documents(uri, modified) VALUES (?, ?)",
            ("example.json", "2026-10-17T00:00:00Z"),
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO cache_metadata VALUES ('build_state', 'building')"
        )
        self.connection.commit()
        request.side_effect = ["example.json,2026-10-18T00:00:00Z\n", "{}"]

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 0)
        self.assertEqual(self.connection.execute(
            "SELECT modified FROM documents WHERE uri = 'example.json'"
        ).fetchone(), ("2026-10-18T00:00:00Z",))
        self.assertEqual(self.connection.execute(
            "SELECT value FROM cache_metadata WHERE key = 'build_state'"
        ).fetchone(), ("ready",))

    @patch("vex_cache._archive_documents")
    @patch("vex_cache._request")
    def test_initial_global_sync_uses_the_published_archive(self, request, archive_documents):
        changes = "example.json,2026-10-18T00:00:00Z\n"
        request.return_value = changes
        archive_documents.return_value = iter([("example.json", "2026-10-18T00:00:00Z", {})])

        self.assertEqual(vex_cache.sync(self.cache_path, "rhel-10", workers=1), 0)

        archive_documents.assert_called_once()
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 1)
        self.assertEqual(self.connection.execute(
            "SELECT value FROM cache_metadata WHERE key = 'scope'"
        ).fetchone(), ("global",))

    @patch("cve_report.get_rpms_from_pyxis")
    def test_in_toto_provenance_resolves_versioned_rpm_inventory(self, get_rpms_from_pyxis):
        get_rpms_from_pyxis.return_value = (
            {"curl"}, {"curl": {"curl-0:8.0-1.el10_2"}},
            {"curl": {"libcurl-0:8.0-1.el10_2"}},
        )
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"digest": {"sha256": "abc"}}],
            "predicate": {"buildConfig": {"tasks": [{"invocation": {"environment": {"annotations": {
                "build.appstudio.redhat.com/target_branch": "rhel-10.2",
            }}}}]}},
        }

        components, module, nvrs, origins = cve_report.parse_in_toto_provenance(statement)

        self.assertEqual(components, {"curl"})
        self.assertEqual(module, "rhel-10")
        self.assertEqual(nvrs["curl"], {"curl-0:8.0-1.el10_2"})
        self.assertEqual(origins["curl"], {"libcurl-0:8.0-1.el10_2"})
        get_rpms_from_pyxis.assert_called_once_with("sha256:abc")

    def test_generated_vex_uses_ga_source_rpm_shape_and_status(self):
        document = cve_report.vex_document(
            {"CVE-TEST-6": [{"cve_id": "CVE-TEST-6", "impact": "IMPORTANT", "cvss": 7.5,
                               "title": "example", "component": "curl", "origin_component": "curl",
                               "origin_nvrs": ["curl-0:8.0-1.el10_2"],
                               "upstream_streams": ["rhel-10.2.z"], "resolution": "known_affected"}]},
            "rhel-10", "image.sbom.json", datetime(2026, 10, 16, tzinfo=timezone.utc),
        )

        self.assertEqual(document["document"]["category"], "csaf_vex")
        self.assertEqual(document["document"]["csaf_version"], "2.0")
        self.assertEqual(document["document"]["tracking"]["revision_history"][0]["summary"],
                         "Last generated version")
        branches = document["product_tree"]["branches"][0]["branches"]
        self.assertIn("rhel-10.2.z", {branch["product"]["product_id"] for branch in branches})
        component = next(branch for branch in branches if branch["category"] == "product_version")
        self.assertEqual(component["name"], "curl")
        self.assertEqual(component["product"]["product_id"], "curl-0:8.0-1.el10_2.src")
        self.assertEqual(
            component["product"]["product_identification_helper"]["purl"],
            "pkg:rpm/redhat/curl@8.0-1.el10_2?arch=src&epoch=0",
        )
        self.assertEqual(document["document"]["tracking"]["id"],
                         "urn:uuid:ef40e5a4-c322-56df-99e8-aaab22268e3f")
        status = document["vulnerabilities"][0]["product_status"]
        self.assertEqual(status, {"known_affected": ["rhel-10.2.z:curl-0:8.0-1.el10_2.src"]})

    def test_generated_vex_preserves_osidb_defer_as_affected_with_remediation(self):
        document = cve_report.vex_document(
            {"CVE-TEST-DEFER": [{"cve_id": "CVE-TEST-DEFER", "impact": "LOW", "title": "example",
                                  "component": "curl", "origin_component": "curl",
                                  "origin_nvrs": ["curl-0:8.0-1.el10_2"], "resolution": "DEFER"}]},
            "rhel-10", "image.sbom.json", datetime(2026, 10, 16, tzinfo=timezone.utc),
        )

        vulnerability = document["vulnerabilities"][0]
        self.assertEqual(vulnerability["product_status"], {
            "known_affected": ["rhel-10.2.z:curl-0:8.0-1.el10_2.src"]
        })
        self.assertEqual(vulnerability["remediations"][0]["category"], "none_available")
        self.assertEqual(vulnerability["remediations"][0]["details"], "Deferred; No Fix Available")

    def test_delegated_osidb_affect_maps_to_known_affected(self):
        self.assertEqual(cve_report.vex_status("DELEGATED"), "known_affected")
        self.assertEqual(cve_report.vex_disposition({"resolution": "DELEGATED"}), "")

    def test_vex_output_is_one_document_for_the_current_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "image.sbom.json.vex.json"
            cve_report.write_vex_document(output_path, "image.sbom.json", "rhel-10", {
                "CVE-TEST-OLD": [{"cve_id": "CVE-TEST-OLD", "impact": "LOW", "title": "old",
                                  "component": "curl", "origin_component": "curl",
                                  "origin_nvrs": ["curl-0:8.0-1.el10_2"], "resolution": "known_affected"}],
            })
            cve_report.write_vex_document(output_path, "image.sbom.json", "rhel-10", {
                "CVE-TEST-NEW": [{"cve_id": "CVE-TEST-NEW", "impact": "IMPORTANT", "title": "new",
                                  "component": "curl", "origin_component": "curl",
                                  "origin_nvrs": ["curl-0:8.0-1.el10_2"], "resolution": "known_affected"}],
                "CVE-TEST-SECOND": [{"cve_id": "CVE-TEST-SECOND", "impact": "LOW", "title": "second",
                                     "component": "bash", "origin_component": "bash",
                                     "origin_nvrs": ["bash-0:5.2-1.el10_2"], "resolution": "known_affected"}],
            })

            document = json.loads(output_path.read_text())
            self.assertEqual(len(document["vulnerabilities"]), 2)
            self.assertEqual(document["vulnerabilities"][0]["cve"], "CVE-TEST-NEW")
            self.assertEqual(document["document"]["aggregate_severity"]["text"], "Important")

    def test_generated_vex_handles_a_versionless_component(self):
        document = cve_report.vex_document({
            "CVE-TEST-NVRLESS": [{"cve_id": "CVE-TEST-NVRLESS", "impact": "LOW", "title": "example",
                                  "component": "curl", "origin_component": "curl",
                                  "origin_nvrs": [], "resolution": "known_affected"}],
        }, "rhel-10", "components.txt", datetime(2026, 10, 16, tzinfo=timezone.utc))

        component = next(branch for branch in document["product_tree"]["branches"][0]["branches"]
                         if branch["category"] == "product_version")
        self.assertEqual(component["product"]["product_identification_helper"]["purl"],
                         "pkg:rpm/redhat/curl?arch=src")


if __name__ == "__main__":
    unittest.main()
