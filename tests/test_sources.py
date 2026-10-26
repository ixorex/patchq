import json
import unittest
from unittest import mock

from patchqueue.sources import cache, cvss, epss, kev, net, nvd, osv
from tests.helpers import FEEDS, IsolatedTest, osv_record


class CvssTests(unittest.TestCase):
    def test_known_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N": 8.6,
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vec, want in cases.items():
            self.assertEqual(cvss.base_score_v3(vec), want, vec)

    def test_no_vector_no_score(self):
        self.assertIsNone(cvss.base_score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertIsNone(cvss.base_score_v3("CVSS:3.1/AV:N"))
        self.assertIsNone(cvss.base_score_v3(""))


class OsvRangeTests(unittest.TestCase):
    def test_fixed_version_from_matching_range(self):
        rec = osv_record("GHSA-xvch-5gv4-984h")  # minimist: <0.2.4 and 1.0.0-<1.2.6
        self.assertEqual(osv.fix_for(rec, "npm", "minimist", "1.2.5"), ("1.2.6", True))
        self.assertEqual(osv.fix_for(rec, "npm", "minimist", "0.1.0"), ("0.2.4", True))
        self.assertEqual(osv.fix_for(rec, "npm", "minimist", "1.2.6")[1], False)

    def test_multi_branch_python(self):
        rec = osv_record("CVE-2021-35042")
        self.assertEqual(osv.fix_for(rec, "PyPI", "Django", "3.2.0")[0], "3.2.5")
        self.assertEqual(osv.fix_for(rec, "PyPI", "django", "3.1.2")[0], "3.1.13")

    def test_last_affected_means_no_fix(self):
        rec = {"id": "X", "affected": [{"package": {"ecosystem": "npm", "name": "a"},
               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "2.0.0"}]}]}]}
        self.assertEqual(osv.fix_for(rec, "npm", "a", "1.5.0"), (None, True))

    def test_versions_compared_by_ecosystem_not_string(self):
        rec = {"id": "X", "affected": [{"package": {"ecosystem": "PyPI", "name": "p"},
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.9"}, {"fixed": "1.10.post1"}]}]}]}
        self.assertEqual(osv.fix_for(rec, "PyPI", "p", "1.10")[0], "1.10.post1")
        self.assertEqual(osv.fix_for(rec, "PyPI", "p", "1.10.post1")[1], False)

    def test_finding_uses_cve_as_primary_id(self):
        f = osv.finding_from_osv(osv_record("GHSA-35jh-r3h4-6jhm"),
                                 {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"})
        self.assertEqual(f["id"], "CVE-2021-23337")
        self.assertIn("GHSA-35jh-r3h4-6jhm", f["aliases"])
        self.assertEqual((f["fixed"], f["cvss"]), ("4.17.21", 7.2))


class FakeNet:
    """Answers like the real APIs, from fixtures."""

    def __init__(self):
        self.calls = []
        self.pkgs = json.loads((FEEDS / "osv-packages.json").read_text())

    def __call__(self, url, payload=None, headers=None, timeout=30, retries=2):
        self.calls.append(url)
        if url == osv.QUERYBATCH_URL:
            res = []
            for q in payload["queries"]:
                k = f"{q['package']['ecosystem']}|{q['package']['name']}|{q['version']}"
                res.append({"vulns": [{"id": i} for i in self.pkgs.get(k, [])]})
            return json.dumps({"results": res}).encode()
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return json.dumps(osv_record(url.rsplit("/", 1)[1])).encode()
        if url == kev.URL:
            return (FEEDS / "kev.json").read_bytes()
        if url.startswith(epss.API):
            scores = json.loads((FEEDS / "epss.json").read_text())
            cves = url.split("cve=")[1].split(",")
            return json.dumps({"data": [{"cve": c, "epss": str(scores[c]), "percentile": "0.5",
                                         "date": "2026-10-25"} for c in cves if c in scores]}).encode()
        if url.startswith(nvd.API):
            return json.dumps({"vulnerabilities": [{"cve": {
                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 6.1, "version": "3.1"}}]},
                "references": [{"url": "https://x", "tags": ["Exploit", "Third Party Advisory"]}]}}]}).encode()
        raise net.FetchError(f"unexpected {url}")


PKGS = [{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        {"name": "PyYAML", "version": "5.3", "ecosystem": "PyPI"},
        {"name": "mkdirp", "version": "0.5.5", "ecosystem": "npm"}]


class LiveAndFallbackTests(IsolatedTest):
    def test_osv_live_then_cached(self):
        fake = FakeNet()
        with mock.patch.object(net, "fetch", fake):
            res, st = osv.lookup(PKGS)
        self.assertTrue(st.live)
        self.assertIsNone(st.error)
        self.assertEqual(len(res[("npm", "lodash", "4.17.15")]), 2)
        self.assertEqual(res[("npm", "mkdirp", "0.5.5")], [])
        self.assertEqual(sum(1 for c in fake.calls if c == osv.QUERYBATCH_URL), 1)  # batched
        # second run within 24h: no network at all (net.fetch raises in tests)
        res2, st2 = osv.lookup(PKGS)
        self.assertEqual(res2.keys(), res.keys())
        self.assertFalse(st2.live)
        self.assertIsNone(st2.error)

    def test_osv_down_uses_stale_cache_and_says_so(self):
        with mock.patch.object(net, "fetch", FakeNet()):
            osv.lookup(PKGS)
        old = "2026-01-01T00:00:00+00:00"
        for k in [("npm", "lodash", "4.17.15"), ("PyPI", "PyYAML", "5.3"), ("npm", "mkdirp", "0.5.5")]:
            p = osv.pkg_cache_path(*k)
            d = cache.read_json(p)
            d["fetched"] = old
            cache.write_json(p, d)
        res, st = osv.lookup(PKGS)  # network disabled
        self.assertIn("network disabled", st.error)
        self.assertEqual(st.as_of, old)
        self.assertEqual(len(res[("npm", "lodash", "4.17.15")]), 2)

    def test_osv_down_and_no_cache_counts_unchecked(self):
        res, st = osv.lookup(PKGS)
        self.assertEqual(st.unchecked, 3)
        self.assertEqual(res, {})

    def test_kev_daily_cache_and_fallback(self):
        fake = FakeNet()
        with mock.patch.object(net, "fetch", fake):
            idx, st = kev.load()
            idx2, _ = kev.load()
        self.assertEqual(sum(1 for c in fake.calls if c == kev.URL), 1)  # once per day, not per CVE
        self.assertEqual(idx["CVE-2014-0160"]["due_date"], "2022-05-25")
        self.assertEqual(idx, idx2)
        p = cache.cache_dir() / "kev.json"
        d = cache.read_json(p)
        d["fetched"] = "2026-01-01T00:00:00+00:00"
        cache.write_json(p, d)
        idx3, st3 = kev.load()
        self.assertEqual(idx3, idx)
        self.assertTrue(st3.error)
        self.assertEqual(st3.as_of, "2026-01-01T00:00:00+00:00")

    def test_kev_garbage_never_overwrites_cache(self):
        with mock.patch.object(net, "fetch", FakeNet()):
            kev.load()
        p = cache.cache_dir() / "kev.json"
        d = cache.read_json(p)
        d["fetched"] = "2026-01-01T00:00:00+00:00"
        cache.write_json(p, d)
        with mock.patch.object(net, "fetch", return_value=b'{"oops": true}'):
            idx, st = kev.load()
        self.assertIn("unexpected KEV format", st.error)
        self.assertIn("CVE-2014-6271", idx)

    def test_kev_missing_entirely_is_loud(self):
        idx, st = kev.load()
        self.assertEqual(idx, {})
        self.assertIn("Tier 0 could not be computed", st.note)

    def test_epss_batch_and_unscored(self):
        fake = FakeNet()
        with mock.patch.object(net, "fetch", fake):
            out, st = epss.load(["CVE-2014-6271", "CVE-2099-0001", "GHSA-not-a-cve"])
        self.assertEqual(out["CVE-2014-6271"]["epss"], 0.975)
        self.assertIsNone(out["CVE-2099-0001"]["epss"])
        self.assertNotIn("GHSA-not-a-cve", out)
        self.assertEqual(len([c for c in fake.calls if c.startswith(epss.API)]), 1)
        out2, st2 = epss.load(["CVE-2014-6271"])  # cached today: no network
        self.assertEqual(out2["CVE-2014-6271"]["epss"], 0.975)

    def test_nvd_cap_and_exploit_tag(self):
        with mock.patch.object(nvd, "DELAY_NO_KEY", 0), mock.patch.object(net, "fetch", FakeNet()):
            out, st = nvd.load(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], max_lookups=2)
        self.assertEqual(len(out), 2)
        self.assertEqual(out["CVE-2026-0001"]["cvss"], 6.1)
        self.assertTrue(out["CVE-2026-0001"]["exploit_ref"])
        self.assertIn("1 CVEs not looked up", st.note)

    def test_net_refuses_plain_http(self):
        self._net.stop()
        try:
            with self.assertRaises(net.FetchError):
                net.fetch("http://example.com/")
        finally:
            self._net.start()


if __name__ == "__main__":
    unittest.main()
