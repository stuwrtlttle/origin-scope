import csv
import json
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

import cve_report
import scanner_csv


HEADERS = [
    "Project id", "Project name", "Component name", "Component version name",
    "Component origin name", "Component origin id", "Component origin version name",
    "Vulnerability id", "Security Risk", "Remediation status", "Match type", "Container image",
]


class ScannerCsvTests(unittest.TestCase):
    def write_csv(self, directory, rows):
        path = Path(directory) / "scan.csv"
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=HEADERS)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def row(self, **overrides):
        row = {
            "Project id": "project", "Project name": "test image", "Component name": "curl",
            "Component version name": "8.12.1-4.el10_2.7", "Component origin name": "Red Hat",
            "Component origin id": "curl/8.12.1-4.el10_2.7/x86_64",
            "Component origin version name": "8.12.1-4.el10_2.7/x86_64",
            "Vulnerability id": "CVE-2026-00001 (BDSA-2026-1)", "Security Risk": "HIGH",
            "Remediation status": "New", "Match type": "SBOM",
            "Container image": "registry.access.redhat.com/ubi10/ubi:10.2",
        }
        row.update(overrides)
        return row

    def test_blackduck_csv_preserves_scanner_fields_and_image(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = scanner_csv.parse_blackduck_csv(self.write_csv(directory, [self.row()]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cve_id, "CVE-2026-00001")
        self.assertEqual(findings[0].component_name, "curl")
        self.assertEqual(findings[0].component_version, "8.12.1-4.el10_2.7")
        self.assertEqual(findings[0].image_reference, "registry.access.redhat.com/ubi10/ubi:10.2")
        self.assertEqual(findings[0].raw["Match type"], "SBOM")
        self.assertEqual(findings[0].scanner_name, "black-duck")

    def test_rhacs_and_trivy_csv_reports_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            rhacs = directory / "rhacs.csv"
            rhacs.write_text(
                "Cluster;Namespace;Deployment;Image;Component;CVE;Severity\n"
                "prod;apps;api;registry.access.redhat.com/ubi10/ubi:10.2;curl;CVE-2026-00002;Critical\n",
                encoding="utf-8",
            )
            trivy = directory / "trivy.csv"
            trivy.write_text(
                "Target,Class,Type,VulnerabilityID,PkgName,InstalledVersion,Severity\n"
                "registry.access.redhat.com/ubi10/ubi:10.2,os-pkgs,rpm,CVE-2026-00003,curl,8.12.1-4.el10_2.7,HIGH\n",
                encoding="utf-8",
            )
            rhacs_findings = scanner_csv.parse_vulnerability_report(rhacs)
            trivy_findings = scanner_csv.parse_vulnerability_report(trivy)
        self.assertEqual((rhacs_findings[0].scanner_name, rhacs_findings[0].component_name), ("rhacs", "curl"))
        self.assertEqual((trivy_findings[0].scanner_name, trivy_findings[0].component_version), ("trivy", "8.12.1-4.el10_2.7"))

    def test_json_and_cve_analyser_input_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            grype = directory / "grype.json"
            grype.write_text(json.dumps({"source": {"target": {"userInput": "registry.access.redhat.com/ubi10/ubi:10.2"}}, "matches": [{
                "vulnerability": {"id": "CVE-2026-00004", "severity": "High"},
                "artifact": {"name": "curl", "version": "8.12.1-4.el10_2.7"},
            }]}), encoding="utf-8")
            simple = directory / "simple.csv"
            simple.write_text("CVE-2026-00005,registry.access.redhat.com/ubi10/ubi:10.2\n", encoding="utf-8")
            grype_findings = scanner_csv.parse_vulnerability_report(grype)
            simple_findings = scanner_csv.parse_vulnerability_report(simple)
        self.assertEqual((grype_findings[0].scanner_name, grype_findings[0].component_name), ("grype", "curl"))
        self.assertEqual((simple_findings[0].scanner_name, simple_findings[0].image_reference),
                         ("cve-analyser", "registry.access.redhat.com/ubi10/ubi:10.2"))

    def test_colorized_grype_text_table_is_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "grype.out"
            path.write_text(
                "NAME                 INSTALLED       FIXED IN        TYPE  VULNERABILITY    SEVERITY  EPSS  RISK\n"
                "curl-minimal         8.12.1-4.el10   8.12.2-1.el10   rpm   CVE-2026-00006   \x1b[31mHigh\x1b[0m      1.0%  2.0\n",
                encoding="utf-8",
            )
            findings = scanner_csv.parse_vulnerability_report(path)
            rows = scanner_csv.grype_text_rows(path)
        self.assertEqual((findings[0].scanner_name, findings[0].component_name), ("grype", "curl-minimal"))
        self.assertEqual((findings[0].component_version, findings[0].scanner_status), ("8.12.1-4.el10", "fix available"))
        self.assertEqual(rows[0]["SEVERITY"], "High")

    def test_grype_csv_is_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "grype.csv"
            path.write_text(
                "NAME,INSTALLED,FIXED IN,TYPE,VULNERABILITY,SEVERITY,EPSS,RISK\n"
                "curl-minimal,8.12.1-4.el10,8.12.2-1.el10,rpm,CVE-2026-00007,High,1.0%,2.0\n",
                encoding="utf-8",
            )
            findings = scanner_csv.parse_vulnerability_report(path)
        self.assertEqual((findings[0].scanner_name, findings[0].component_name), ("grype", "curl-minimal"))
        self.assertEqual(findings[0].component_version, "8.12.1-4.el10")

    def test_image_reference_requires_tag_or_digest(self):
        with self.assertRaisesRegex(scanner_csv.ScannerInputError, "explicit image tag"):
            scanner_csv.parse_image_reference("registry.access.redhat.com/ubi10/ubi")
        registry, repository, tag, digest = scanner_csv.parse_image_reference("ubi10/ubi:10.2")
        self.assertEqual((registry, repository, tag, digest), ("registry.access.redhat.com", "ubi10/ubi", "10.2", None))

    def test_catalog_resolution_selects_exact_architecture(self):
        calls = []
        def fetch(url):
            calls.append(url)
            return {"data": [
                {"_id": "arm", "architecture": "arm64", "image_id": "sha256:" + "a" * 64},
                {"_id": "amd", "architecture": "amd64", "image_id": "sha256:" + "b" * 64,
                 "repositories": [{"repository": "ubi10/ubi", "image_advisory_id": "RHBA-2026:1", "tags": [{"name": "10.2"}]}]},
            ]}
        subject = scanner_csv.resolve_redhat_image("registry.redhat.io/ubi10/ubi:10.2", fetch_json=fetch)
        self.assertEqual(subject.catalog_image_id, "amd")
        self.assertEqual(subject.resolved_reference, f"registry.redhat.io/ubi10/ubi@sha256:{'b' * 64}")
        self.assertIn("registry.redhat.io", calls[0])

    def test_registry_digest_resolves_exact_image_then_fetches_its_rpm_manifest(self):
        digest = "sha256:" + "c" * 64
        calls = []

        def fetch(url):
            calls.append(url)
            if url.endswith("/rpm-manifest"):
                return {"rpms": [{"name": "curl", "nvra": "curl-8.0-1.el10.x86_64"}]}
            return {"_id": "catalog-image", "architecture": "amd64", "image_id": digest}

        subject = scanner_csv.resolve_redhat_image(
            f"registry.redhat.io/ubi10/ubi@{digest}", fetch_json=fetch
        )
        manifest = scanner_csv.fetch_rpm_manifest(subject, fetch_json=fetch)

        self.assertEqual(subject.resolved_reference, f"registry.redhat.io/ubi10/ubi@{digest}")
        self.assertIn(
            f"/images/registry/registry.redhat.io/repository/ubi10%2Fubi/manifest_digest/sha256%3A{'c' * 64}",
            calls[0],
        )
        self.assertEqual(calls[1],
                         "https://catalog.redhat.com/api/containers/v1/images/id/catalog-image/rpm-manifest")
        self.assertEqual(manifest[0]["name"], "curl")

    def test_report_name_is_matched_to_catalog_brew_package_and_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openshift-gitops-operator-container_v1.21.5-4_2026-10-06_grype.out"
            path.write_text(
                "NAME  INSTALLED  FIXED IN  TYPE  VULNERABILITY  SEVERITY\n"
                "curl  8.0        8.1       rpm   CVE-2026-00008  High\n",
                encoding="utf-8",
            )
            calls = []
            def fetch(url):
                calls.append(url)
                return {"data": [{
                    "architecture": "amd64",
                    "brew": {
                        "package": "openshift-gitops-operator-container",
                        "build": "openshift-gitops-operator-container-v1.21.5-4",
                    },
                    "repositories": [{
                        "repository": "openshift-gitops-1/gitops-rhel9-operator",
                        "image_advisory_id": "RHSA-2026:1",
                        "tags": [{"name": "v1.21.5-4"}],
                    }],
                }]}
            candidates = scanner_csv.suggest_image_candidates(path, fetch_json=fetch)
        self.assertEqual(candidates[0].reference,
                         "registry.access.redhat.com/openshift-gitops-1/gitops-rhel9-operator:v1.21.5-4")
        self.assertEqual(candidates[0].score, 100)
        self.assertIn("brew.package", calls[0])
        self.assertIn("Brew build matches", " ".join(candidates[0].reasons))

    def test_rhel_major_from_scanned_rpms_selects_the_matching_repository_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openshift-gitops-operator-container_v1.21.5-4_grype.out"
            path.write_text(
                "NAME                 INSTALLED       FIXED IN        TYPE  VULNERABILITY    SEVERITY  EPSS  RISK\n"
                "curl                 8.0-1.el9_6.1   8.1             rpm   CVE-2026-00010   High      1.0%  2.0\n"
                "openssl              3.2-1.el9_6.1   3.3             rpm   CVE-2026-00011   High      1.0%  2.0\n"
                "zlib                 1.3-1.el9_6.1   1.4             rpm   CVE-2026-00012   High      1.0%  2.0\n",
                encoding="utf-8",
            )
            def fetch(url):
                if "gitops-rhel9-operator" in url:
                    return {"data": [{
                        "architecture": "amd64", "repositories": [{
                            "repository": "openshift-gitops-1/gitops-rhel9-operator",
                            "tags": [{"name": "v1.21.5-4"}],
                        }],
                    }]}
                return {"data": [{
                    "architecture": "amd64",
                    "brew": {"package": "openshift-gitops-operator-container"},
                    "repositories": [{
                        "repository": "openshift-gitops-1/gitops-rhel8-operator",
                        "tags": [{"name": "v1.21.5-4"}],
                    }],
                }]}
            candidates = scanner_csv.suggest_image_candidates(path, fetch_json=fetch)
        self.assertEqual(candidates[0].repository, "openshift-gitops-1/gitops-rhel9-operator")
        self.assertIn("predominantly RHEL 9", " ".join(candidates[0].reasons))

    def test_catalog_sbom_and_evidence_keep_origin_confidence_honest(self):
        subject = scanner_csv.ImageSubject(
            "ubi10/ubi:10.2", "registry.access.redhat.com/ubi10/ubi@sha256:" + "a" * 64,
            "registry.access.redhat.com", "ubi10/ubi", "10.2", "sha256:" + "a" * 64,
            "amd64", "image", "https://catalog.example/image", "https://catalog.example/rpms", "RHBA-2026:1",
        )
        rpms = [{"name": "curl", "version": "8.12.1", "release": "4.el10_2.7", "architecture": "x86_64",
                 "nvra": "curl-8.12.1-4.el10_2.7.x86_64"}]
        with tempfile.TemporaryDirectory() as directory:
            sbom_path = Path(directory) / "catalog-sbom.cdx.json"
            evidence_path = Path(directory) / "scanner-evidence.json"
            results_path = Path(directory) / "results.json"
            scanner_csv.write_catalog_sbom(sbom_path, subject, rpms)
            components, module, nvrs, _ = cve_report.parse_input(sbom_path)
            finding = scanner_csv.ScannerFinding("CVE-2026-00001", "curl", "8.12.1-4.el10_2.7", "Red Hat", "SBOM", "New", "HIGH", "", {})
            payload = scanner_csv.write_scanner_evidence(evidence_path, [finding], subject, rpms)
            saved = json.loads(evidence_path.read_text())
            results_path.write_text(json.dumps({"findings": [
                {"cveId": "CVE-2026-00001"}, {"cveId": "CVE-2023-44487"},
            ]}), encoding="utf-8")
            annotated = scanner_csv.reconcile_scanner_results(results_path, payload)
        self.assertEqual(components, {"curl"})
        self.assertEqual(module, "rhel-10")
        self.assertIn("curl-8.12.1-4.el10_2.7", nvrs["curl"])
        self.assertEqual(payload["findings"][0]["evidence_confidence"], "unresolved")
        self.assertEqual(saved["findings"][0]["origin_kind"], "unknown")
        self.assertEqual([item["cveId"] for item in annotated["findings"]], ["CVE-2026-00001"])
        self.assertNotIn("scannerRationale", annotated["findings"][0])
        self.assertIn("exact RPM name/version", scanner_csv.render_scanner_evidence_markdown(payload))

    def test_scanner_only_results_keep_unverified_scanner_findings(self):
        subject = scanner_csv.ImageSubject(
            "ubi10/ubi:10.2", "registry.access.redhat.com/ubi10/ubi@sha256:" + "a" * 64,
            "registry.access.redhat.com", "ubi10/ubi", "10.2", "sha256:" + "a" * 64,
            "amd64", "image", "https://catalog.example/image", "https://catalog.example/rpms", None,
        )
        finding = scanner_csv.ScannerFinding(
            "CVE-2026-00001", "curl", "8.12.1", "rpm", "grype table", "reported", "HIGH", "", {}, "grype",
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "scanner-evidence.json"
            results_path = Path(directory) / "results.json"
            evidence = scanner_csv.write_scanner_evidence(evidence_path, [finding], subject, [])
            results_path.write_text(json.dumps({"findings": [{"cveId": "CVE-2023-44487"}]}), encoding="utf-8")
            annotated = scanner_csv.reconcile_scanner_results(results_path, evidence)
        self.assertEqual([item["cveId"] for item in annotated["findings"]], ["CVE-2026-00001"])
        self.assertEqual(annotated["findings"][0]["remediationStatus"], "unverified")

    def test_scanner_results_do_not_include_scanner_rationale(self):
        findings = []
        for evidence in ([{"matcher": "rpm-matcher"}], [{"matcher": "cpe-matcher"}]):
            findings.append({
                "cve_id": "CVE-2026-00001",
                "scanner": {
                    "name": "grype", "component": "curl", "version": "8.12.1",
                    "match_type": "grype table", "remediation_status": "reported", "severity": "HIGH",
                },
                "scanner_match_rationale": {
                    "kind": "grype-table",
                    "summary": "Grype's table reports the package/CVE pair but omits matcher evidence.",
                    "evidence": evidence,
                },
                "image_membership": "component was not found in the resolved image RPM manifest",
                "matched_catalog_rpms": [],
                "limitation": "",
            })
        with tempfile.TemporaryDirectory() as directory:
            results_path = Path(directory) / "results.json"
            results_path.write_text(json.dumps({"findings": [{
                "cveId": "CVE-2026-00001", "scannerRationale": [{"decision": "stale"}],
            }]}), encoding="utf-8")
            annotated = scanner_csv.reconcile_scanner_results(results_path, {"findings": findings})

        self.assertNotIn("scannerRationale", annotated["findings"][0])

    def test_podman_validation_uses_local_rpm_database_with_epoch(self):
        subject = scanner_csv.ImageSubject(
            "ubi9/ubi:9.8", "registry.access.redhat.com/ubi9/ubi@sha256:" + "a" * 64,
            "registry.access.redhat.com", "ubi9/ubi", "9.8", "sha256:" + "a" * 64,
            "amd64", "catalog-id", "https://catalog.example", "https://catalog.example/rpms", None,
        )
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            if command[1] == "info":
                return SimpleNamespace(returncode=0, stdout="{}", stderr="")
            if command[1] == "pull":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(
                returncode=0,
                stdout="openssl-libs\t1\t3.5.8\t1.el9_8\tx86_64\n",
                stderr="",
            )

        validation = scanner_csv.inspect_image_with_podman(subject, runner=runner)
        finding = scanner_csv.ScannerFinding(
            "CVE-2026-00001", "openssl-libs", "1:3.5.8-1.el9_8", "rpm", "grype table",
            "reported", "HIGH", "", {}, "grype",
        )
        evidence = scanner_csv.finding_evidence([finding], subject, [], validation)

        self.assertEqual(validation["state"], "verified")
        self.assertEqual(evidence[0]["evidence_confidence"], "confirmed")
        self.assertIn("local image RPM database", evidence[0]["image_membership"])
        self.assertEqual(evidence[0]["matched_podman_rpms"][0]["nvra"], "openssl-libs-3.5.8-1.el9_8.x86_64")
        self.assertTrue(any(command[1] == "run" for command in calls))

    def test_scanner_review_csv_exports_status_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            results_path = Path(directory) / "results.json"
            csv_path = Path(directory) / "scanner-review.csv"
            results_path.write_text(json.dumps({"findings": [{
                "cveId": "CVE-2026-00001",
                "impact": "IMPORTANT",
                "cvss": 7.5,
                "remediationStatus": "fixed",
                "advisories": ["RHSA-2026:1234"],
                "components": [{
                    "originComponent": "curl",
                    "originNvrs": ["curl-8.12.1-4.el10_2.7"],
                    "upstreamStreams": ["rhel-10.2"],
                }],
            }]}), encoding="utf-8")

            scanner_csv.write_scanner_review_csv(csv_path, results_path, {"findings": [{
                "cve_id": "CVE-2026-00001",
                "scanner": {
                    "name": "grype", "component": "curl", "version": "8.12.1",
                    "match_type": "exact", "remediation_status": "reported", "severity": "HIGH",
                },
                "image_membership": "exact RPM name/version",
                "matched_catalog_rpms": [{"nvra": "curl-8.12.1-4.el10_2.7.x86_64"}],
                "matched_podman_rpms": [],
                "limitation": "Scanner match rules were not included.",
            }]})
            with csv_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["CVE"], "CVE-2026-00001")
        self.assertEqual(rows[0]["Status"], "fixed")
        self.assertEqual(rows[0]["Origin component NVR"], "curl-8.12.1-4.el10_2.7")
        self.assertEqual(rows[0]["BOMQ upstream stream(s)"], "rhel-10.2")
        self.assertIn("RHSA-2026:1234", rows[0]["Advisory URLs"])
        self.assertEqual(rows[0]["Scanner"], "grype")
        self.assertNotIn("Scanner rationale", rows[0])

    def test_grype_json_match_details_are_explained_by_the_rule_database(self):
        finding = scanner_csv.ScannerFinding(
            "CVE-2026-00001", "curl", "8.0", "rpm", "grype json", "reported", "HIGH", "",
            {"Grype match details": [{
                "type": "cpe-match", "matcher": "rpm-matcher",
                "searchedBy": {"namespace": "nvd:cpe"},
                "found": {"versionConstraint": "< 8.1"},
            }]},
            scanner_name="grype",
        )

        rationale = scanner_csv.scanner_match_rationale(finding)

        self.assertEqual(rationale["kind"], "grype-match-details")
        self.assertIn("CPE association", rationale["summary"])
        self.assertEqual(rationale["evidence"][0]["matcher"], "rpm-matcher")

    def test_catalog_sbom_preserves_source_rpm_for_osidb_and_bomq(self):
        subject = scanner_csv.ImageSubject(
            "image:tag", "registry.access.redhat.com/example@sha256:" + "b" * 64,
            "registry.access.redhat.com", "example", "tag", "sha256:" + "b" * 64,
            "amd64", "image", "https://catalog.example/image", "https://catalog.example/rpms", None,
        )
        rpms = [{
            "name": "alternatives", "version": "1.24", "release": "2.el9", "architecture": "x86_64",
            "nvra": "alternatives-1.24-2.el9.x86_64", "srpm_name": "chkconfig",
            "srpm_nevra": "chkconfig-0:1.24-2.el9.src",
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.cdx.json"
            document = scanner_csv.write_catalog_sbom(path, subject, rpms)
            components, module, nvrs, origins = cve_report.parse_input(path)
        self.assertEqual(components, {"chkconfig"})
        self.assertEqual(module, "rhel-9")
        self.assertEqual(nvrs["chkconfig"], {"chkconfig-1.24-2.el9"})
        self.assertEqual(origins["chkconfig"], {"alternatives-1.24-2.el9"})
        self.assertEqual(document["components"][0]["properties"][2]["value"], "chkconfig-1.24-2.el9")


if __name__ == "__main__":
    unittest.main()
