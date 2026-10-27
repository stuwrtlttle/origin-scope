import unittest

import cve_report_app
import originscope_app


class OriginScopeAppTests(unittest.TestCase):
    def test_originscope_ui_exposes_versioned_profiles_and_evidence_bundle(self):
        html = originscope_app.build_html(cve_report_app.APP_HTML)

        self.assertIn("OriginScope", html)
        self.assertIn('id="assessment-profile"', html)
        self.assertIn("critical-exposure-gate-v1", html)
        self.assertIn("assessmentProfile", html)
        self.assertIn('id="assessment-bundle-link"', html)
        self.assertIn("assessmentBundleReady", html)
        self.assertIn('id="assessment-verdict"', html)
        self.assertIn("renderAssessmentVerdict", html)


if __name__ == "__main__":
    unittest.main()
