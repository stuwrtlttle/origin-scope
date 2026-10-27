import copy
import unittest

import assessment_policy


class AssessmentPolicyTests(unittest.TestCase):
    def test_critical_exposure_gate_fails_for_an_active_critical_cve(self):
        verdict = assessment_policy.evaluate(
            assessment_policy.profile("critical-exposure-gate-v1"),
            {
                "summary": {"source": "OSIDB tracker"},
                "findings": [{
                    "cveId": "CVE-2026-00001",
                    "impact": "CRITICAL",
                    "remediationStatus": "unfixed",
                    "components": [{"originNvrs": ["openssl-3.0.0-1.el10"]}],
                }],
            },
        )

        self.assertEqual(verdict["verdict"], "fail")
        rule = next(item for item in verdict["rules"] if item["id"] == "no-critical-active-cves")
        self.assertEqual(rule["status"], "fail")
        self.assertEqual(rule["cveIds"], ["CVE-2026-00001"])

    def test_a_current_profile_waiver_is_explicit_in_the_verdict(self):
        profile = copy.deepcopy(assessment_policy.profile("critical-exposure-gate-v1"))
        profile["waivers"] = [{
            "ruleId": "no-critical-active-cves",
            "cveId": "CVE-2026-00001",
            "reason": "Approved temporary exception",
            "expires": "2999-01-01",
        }]
        verdict = assessment_policy.evaluate(profile, {
            "summary": {"source": "OSIDB tracker"},
            "findings": [{
                "cveId": "CVE-2026-00001",
                "impact": "CRITICAL",
                "remediationStatus": "unfixed",
                "components": [{"originNvrs": ["openssl-3.0.0-1.el10"]}],
            }],
        })

        self.assertEqual(verdict["verdict"], "pass")
        rule = next(item for item in verdict["rules"] if item["id"] == "no-critical-active-cves")
        self.assertEqual(rule["status"], "waived")
        self.assertEqual(rule["waivers"][0]["reason"], "Approved temporary exception")

    def test_report_only_profile_keeps_active_findings_informational(self):
        verdict = assessment_policy.evaluate(
            assessment_policy.profile(),
            {"summary": {}, "findings": [{"cveId": "CVE-2026-00002", "remediationStatus": "unfixed"}]},
        )

        self.assertEqual(verdict["verdict"], "pass")
        observed = next(item for item in verdict["rules"] if item["id"] == "active-cves-observed")
        self.assertEqual(observed["count"], 1)
        self.assertEqual(observed["status"], "pass")


if __name__ == "__main__":
    unittest.main()
