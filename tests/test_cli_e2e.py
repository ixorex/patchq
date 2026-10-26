"""End-to-end: `patchq scan` on the sample homelab repo, then decisions, then queue."""
import contextlib
import datetime as dt
import io
import json
from unittest import mock

from patchqueue import cli, state
from patchqueue.sources import net
from tests.helpers import IsolatedTest, seed_cache
from tests.test_sources import FakeNet


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def future(days=20):
    return (dt.date.today() + dt.timedelta(days=days)).isoformat()


class EndToEndTests(IsolatedTest):
    def scan_json(self, *extra):
        code, out, err = run("scan", str(self.sample), "--json", *extra)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def setUp(self):
        super().setUp()
        self.sample = self.copy_sample()

    def test_full_queue_offline_from_cache(self):
        seed_cache()
        q = self.scan_json("--offline")
        tiers = [(i["id"], i["tier"]) for i in q["items"]]
        self.assertEqual(tiers, [
            ("CVE-2014-0160", 0),   # KEV, earlier CISA due date
            ("CVE-2014-6271", 0),   # KEV
            ("CVE-2020-14343", 1),  # EPSS 0.12
            ("CVE-2021-44906", 1),  # CVSS 9.8, exposed web -> up one tier
            ("CVE-2021-23337", 1),
            ("CVE-2020-8203", 1),
            ("CVE-2021-35042", 2),  # EPSS 0.035
            ("CVE-2019-10906", 2),  # CVSS 8.6 (api + worker merged)
            ("CVE-2023-37920", 2),
            ("CVE-2024-22195", 3),  # low signal, major bump
            ("CVE-2011-3374", 3),   # no fix yet
        ])
        for i in q["items"]:  # every item carries the required fields
            for k in ("package", "installed", "id", "why", "breaks", "fix_cmd", "fix_note"):
                self.assertIn(k, i)
            self.assertTrue(i["fixed"] or "no fix yet" in i["why"])
        jinja = next(i for i in q["items"] if i["id"] == "CVE-2019-10906")
        self.assertEqual({l["file"] for l in jinja["locations"]}, {"api/requirements.txt", "worker/poetry.lock"})
        self.assertEqual(len(jinja["fix_cmd"].splitlines()), 2)
        warnings = " ".join(w for s in q["scans"] for w in s["warnings"])
        for expected in ("yarn.lock", "nginx:1.25-alpine", "requests>=2.25", "built locally"):
            self.assertIn(expected, warnings)

    def test_live_run_with_fake_apis(self):
        with mock.patch.object(net, "fetch", FakeNet()):
            q = self.scan_json("--nvd-max", "0")
        self.assertEqual(q["items"][0]["id"], "CVE-2014-0160")
        self.assertTrue(q["sources"]["OSV"]["live"])
        self.assertTrue(q["sources"]["KEV"]["live"])
        self.assertIsNone(q["sources"]["OSV"]["error"])

    def test_all_feeds_down_no_cache_is_loud_not_silent(self):
        code, out, err = run("scan", str(self.sample))
        self.assertEqual(code, 0)
        self.assertIn("vulnerability matching did NOT run", out)
        self.assertIn("NOT mean you're clean", out)
        self.assertIn("⚠ OSV", out)
        self.assertIn("Tier 0 could not be computed", out)
        self.assertIn("PatchQ is a triage aid, not a guarantee.", out)

    def test_decisions_persist_with_history(self):
        seed_cache()
        run("scan", str(self.sample), "--offline")
        rc = future()
        self.assertEqual(run("defer", "CVE-2014-6271", "--reason", "box retired next sprint", "--recheck", rc)[0], 0)
        self.assertEqual(run("ignore", "GHSA-35jh-r3h4-6jhm", "--reason", "template() never called")[0], 0)  # alias
        code, out, _ = run("done", "CVE-2020-14343")
        self.assertIn("Re-run `patchq scan`", out)

        code, out, _ = run("queue", "--json")
        items = {i["id"]: i for i in json.loads(out)["items"]}
        self.assertEqual((items["CVE-2014-6271"]["tier"], items["CVE-2014-6271"]["status"]), (3, "deferred"))
        self.assertEqual(items["CVE-2014-6271"]["recheck"], rc)
        self.assertEqual(items["CVE-2021-23337"]["status"], "not_affected")
        self.assertEqual(items["CVE-2020-14343"]["status"], "patched_but_present")  # still in the lockfile

        # change your mind: the old decision stays in history
        run("defer", "CVE-2014-6271", "--reason", "still waiting on vendor", "--recheck", future(40))
        dec = state.load()["decisions"]["CVE-2014-6271"]
        self.assertEqual(dec["reason"], "still waiting on vendor")
        self.assertEqual(dec["history"][0]["reason"], "box retired next sprint")

        code, out, _ = run("queue", "--all")
        self.assertIn("history:", out)
        self.assertIn("box retired next sprint", out)

    def test_decision_validation(self):
        self.assertEqual(run("defer", "CVE-2014-6271", "--reason", "x", "--recheck", "2001-01-01")[0], 2)
        self.assertEqual(run("defer", "CVE-2014-6271", "--reason", "x", "--recheck", "soon")[0], 2)
        self.assertEqual(run("ignore", "$(rm -rf ~)", "--reason", "x")[0], 2)
        with self.assertRaises(SystemExit):  # argparse: --recheck is required
            run("defer", "CVE-1", "--reason", "x")

    def test_patched_item_disappears_after_upgrade(self):
        seed_cache()
        run("scan", str(self.sample), "--offline")
        run("done", "CVE-2020-14343")
        req = self.sample / "api" / "requirements.txt"
        req.write_text(req.read_text().replace("PyYAML==5.3", "PyYAML==5.4"))
        # 5.4 has no cached OSV entry in the fixtures: seed it as clean, like a live run would
        from patchqueue.sources import cache, osv
        cache.write_json(osv.pkg_cache_path("PyPI", "PyYAML", "5.4"), {"fetched": cache.now_iso(), "ids": []})
        code, out, _ = run("scan", str(self.sample), "--offline", "--json")
        ids = [i["id"] for i in json.loads(out)["items"]]
        self.assertNotIn("CVE-2020-14343", ids)
        self.assertEqual(state.load()["decisions"]["CVE-2020-14343"]["status"], "patched")  # history kept

    def test_import_flag_and_single_file_scan(self):
        seed_cache()
        lock = self.sample / "web" / "package-lock.json"
        code, out, err = run("scan", str(lock), "--offline", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual({i["package"] for i in json.loads(out)["items"]}, {"lodash", "minimist"})

    def test_queue_before_scan_and_corrupt_state(self):
        self.assertEqual(run("queue")[0], 1)
        (self.home / "queue.json").write_text("{broken")
        code, _, err = run("queue")
        self.assertEqual(code, 2)
        self.assertIn("won't overwrite", err)
        self.assertEqual((self.home / "queue.json").read_text(), "{broken")

    def test_state_file_is_private(self):
        seed_cache()
        run("scan", str(self.sample), "--offline")
        self.assertEqual((self.home / "queue.json").stat().st_mode & 0o777, 0o600)

    def test_missing_path(self):
        code, _, err = run("scan", str(self.sample / "nope"))
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)
