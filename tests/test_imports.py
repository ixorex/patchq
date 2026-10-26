import unittest

from patchqueue import imports
from patchqueue.sources import osv
from tests.helpers import FIX, SAMPLE, IsolatedTest, seed_cache

R = FIX / "reports"


def core(findings):
    return {(f["id"], f["package"], f["installed"], f["fixed"]) for f in findings}


class ImportEquivalenceTests(IsolatedTest):
    """Trivy / Grype / OSV-Scanner reports must yield the same queue items as a direct OSV query."""

    def direct(self):
        seed_cache()
        pkg = {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}
        res, _ = osv.lookup([pkg], offline=True)
        return [osv.finding_from_osv(r, pkg) for r in res[osv.key(pkg)]]

    def test_trivy_equals_osv(self):
        self.assertEqual(core(imports.load(R / "trivy-lodash.json").findings), core(self.direct()))

    def test_grype_equals_osv(self):
        got = imports.load(R / "grype-lodash.json").findings
        self.assertEqual(core(got), core(self.direct()))
        self.assertTrue(all(f["aliases"] for f in got))  # GHSA kept as alias of the CVE

    def test_osv_scanner_equals_osv(self):
        self.assertEqual(core(imports.load(R / "osv-scanner-lodash.json").findings), core(self.direct()))

    def test_expected_items(self):
        self.assertEqual(core(self.direct()), {
            ("CVE-2021-23337", "lodash", "4.17.15", "4.17.21"),
            ("CVE-2020-8203", "lodash", "4.17.15", "4.17.19"),
        })


class TrivyImageTests(unittest.TestCase):
    def test_os_packages_and_no_fix(self):
        rr = imports.load(SAMPLE / "trivy-legacy.json")
        self.assertEqual(rr.kind, "trivy")
        self.assertEqual(rr.images, {"example/legacy-shell:1.0"})
        by = {f["package"]: f for f in rr.findings}
        self.assertEqual(by["bash"]["ecosystem"], "Debian")
        self.assertEqual(by["bash"]["fixed"], "4.2+dfsg-0.1+deb7u1")
        self.assertEqual(by["bash"]["cvss"], 9.8)
        self.assertIsNone(by["apt"]["fixed"])

    def test_multi_branch_fixed_versions(self):
        self.assertEqual(imports._pick_fix("2.4.1, 2.3.5", "2.3.1", "npm"), "2.3.5")
        self.assertEqual(imports._pick_fix("2.4.1, 2.3.5", "2.4.0", "npm"), "2.4.1")
        self.assertIsNone(imports._pick_fix("", "1.0", "npm"))

    def test_unknown_json_is_a_clear_error(self):
        with self.assertRaises(imports.ReportError):
            imports.load(R / "not-a-report.json")


if __name__ == "__main__":
    unittest.main()
