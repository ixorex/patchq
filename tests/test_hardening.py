"""Hostile-input hardening: everything a scanned repo or report controls must not hang,
crash, read outside the scan root, or reach the terminal / browser unescaped."""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock
from types import SimpleNamespace
import urllib.error
import urllib.request
from pathlib import Path

from patchqueue import cli, discovery, fixcmd, imports, miniyaml, parsers, rank, render, scan, service, state, version, web
from patchqueue.model import new_finding
from patchqueue.parsers import docker as dk, npm as npmp, python as pyp
from patchqueue.sources import net, nvd, osv
from tests.helpers import IsolatedTest

BIG = 200_000


class LinearTimeTests(unittest.TestCase):
    """Each of these took seconds-to-forever before the fix (quadratic/cubic regex backtracking)."""

    def fast(self, fn, budget=1.0):
        s = time.time()
        fn()
        self.assertLess(time.time() - s, budget)

    def test_parsers_and_version_are_linear(self):
        self.fast(lambda: list(dk._IMAGE_LINE.finditer("\n" * BIG + "x")))
        self.fast(lambda: list(dk._IMAGE_LINE.finditer((" " * 50 + "\n") * (BIG // 50) + "x")))
        self.fast(lambda: list(dk._FROM.finditer("\n" * BIG + "x")))
        self.fast(lambda: pyp._REQ.match("a" + " " * BIG + "x"))
        self.fast(lambda: version.compare(" " * BIG + "x", "1.0", "npm"))
        self.fast(lambda: version.compare("1." * BIG, "1.0", "PyPI"))
        self.fast(lambda: miniyaml.loads("k" + " " * BIG + "x: y"))
        self.fast(lambda: miniyaml.loads("a" + " " * BIG + "b"))

    def test_behaviour_unchanged(self):
        self.assertEqual(pyp._REQ.match("Django [bcrypt] == 3.2.0").group(1, 4), ("Django", "3.2.0"))
        self.assertEqual(npmp._RANGE.match("^ 1.2.3").group(2), "1.2.3")
        self.assertEqual(miniyaml.loads("image: nginx:1.0\nurl: http://x:80/\n'q: k': v"),
                         {"image": "nginx:1.0", "url": "http://x:80/", "q: k": "v"})
        self.assertEqual(version.compare(" v1.2.3 ", "1.2.3", "npm"), 0)


class HostileInputTests(IsolatedTest):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_deeply_nested_json_is_a_warning_not_a_crash(self):
        (self.root / "trivy-x.json").write_text('{"SchemaVersion":2,"Results":' + "[" * BIG + "]" * BIG + "}")
        (self.root / "package-lock.json").write_text("[" * BIG + "]" * BIG)
        rec = scan.scan(str(self.root), offline=True, use_nvd=False)
        text = " ".join(rec["warnings"])
        self.assertIn("not a Trivy", text)
        self.assertIn("NOT checked", text)

    def test_requirements_include_cannot_escape_scan_root(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        (outside / "secrets.txt").write_text("password==hunter2\n")
        app = self.root / "app"
        app.mkdir()
        (app / "requirements.txt").write_text(f"-r {outside / 'secrets.txt'}\n-r ../../{outside.name}/secrets.txt\nflask==2.0.1\n")
        res = parsers.parse(app / "requirements.txt", "requirements", root=self.root)
        self.assertEqual([p["name"] for p in res.packages], ["flask"])
        self.assertEqual(sum("outside the scanned folder" in w for w in res.warnings), 2)
        (self.root / "common.txt").write_text("click==8.0.0\n")  # inside root, one level up: allowed
        (app / "requirements.txt").write_text("-r ../common.txt\n")
        res = parsers.parse(app / "requirements.txt", "requirements", root=self.root)
        self.assertEqual([p["name"] for p in res.packages], ["click"])

    def test_no_command_for_paths_with_control_or_bidi_chars(self):
        for bad in ("/srv/app\x1b]0;pwned\x07", "/srv/‮evil", "/srv/a​b"):
            it = new_finding(id="CVE-1", package="lodash", installed="1.0.0", fixed="1.0.1", ecosystem="npm",
                             locations=[{"file": "package-lock.json", "dir": bad, "kind": "npm-lock", "direct": True}])
            cmd, note = fixcmd.command(it)
            self.assertEqual(cmd, "")
            self.assertIn("control or invisible", note)

    def test_terminal_output_has_no_escapes_or_bidi(self):
        it = new_finding(id="CVE-1\x1b[2J", package="pkg‮", installed="1\x07", fixed="2", ecosystem="npm",
                         summary="x\x1b]8;;http://e\x07", locations=[{"file": "f\x1b[1m", "system": "s⁦", "kind": "npm-lock"}])
        ranked = rank.rank([it], today="2026-10-27")
        from patchqueue import group
        groups, decided = group.group(ranked)
        out = render.render_grouped(groups, decided, [{"label": "/x/\x1b[31mevil", "scanned_at": ""}], {}, show_all=True)
        out += render.render_queue(ranked, [], {}, show_all=True)
        for ch in ("\x1b", "\x07", "‮", "⁦"):
            self.assertNotIn(ch, out)


class WrongTypeTests(IsolatedTest):
    """Wrong-typed fields in scanner reports / feeds / queue.json must warn, not crash."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_wrong_typed_trivy_report_warns_not_crash(self):
        data = {"SchemaVersion": 2, "ArtifactName": "img", "Results": [
            "not-an-object",
            {"Type": "npm", "Target": "x", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2026-0001", "PkgName": "lodash", "InstalledVersion": "4.17.15",
                 "CVSS": ["not-a-dict"]},
                {"VulnerabilityID": "CVE-2026-0002", "PkgName": "lodash", "InstalledVersion": "4.17.15",
                 "CVSS": {"nvd": {"V3Score": "high"}}},
                {"VulnerabilityID": "CVE-2026-0003", "PkgName": "lodash", "InstalledVersion": "4.17.15",
                 "CVSS": {"nvd": {"V3Score": 9.8}}, "FixedVersion": "4.17.21"},
            ]},
        ]}
        res = imports._trivy(data, "trivy-x.json")
        self.assertEqual([(f["id"], f["cvss"]) for f in res.findings],
                         [("CVE-2026-0001", None), ("CVE-2026-0002", None), ("CVE-2026-0003", 9.8)])
        self.assertEqual(res.findings[2]["fixed"], "4.17.21")
        self.assertIn("malformed Trivy result entry", " ".join(res.warnings))
        self.assertIn("ignoring non-numeric CVSS score", " ".join(res.warnings))

    def test_wrong_typed_grype_report_warns_not_crash(self):
        data = {"source": "not-a-dict", "matches": [
            "not-an-object",
            {"vulnerability": {"id": "CVE-2026-0001", "cvss": [{"version": "3.1", "metrics": {"baseScore": "bad"}}]},
             "artifact": {"name": "lodash", "version": "4.17.15", "type": "npm"}},
            {"vulnerability": {"id": "CVE-2026-0002", "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.5}}]},
             "artifact": {"name": "lodash", "version": "4.17.15", "type": "npm"}},
        ]}
        res = imports._grype(data, "grype-x.json")
        self.assertEqual([(f["id"], f["cvss"]) for f in res.findings],
                         [("CVE-2026-0001", None), ("CVE-2026-0002", 7.5)])
        self.assertIn("malformed Grype match entry", " ".join(res.warnings))
        self.assertIn("ignoring non-numeric CVSS score", " ".join(res.warnings))

    def test_wrong_typed_osv_scanner_report_warns_not_crash(self):
        data = {"results": [
            "not-an-object",
            {"source": {"path": "app/package-lock.json"}, "packages": [
                {"package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                 "vulnerabilities": ["not-an-object",
                                     {"id": "CVE-2021-23337", "aliases": ["GHSA-35jh-r3h4-6jhm"],
                                      "summary": "s", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                                                    "ranges": [{"type": "ECOSYSTEM", "events": [
                                                                        {"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}]},
            ]},
        ]}
        res = imports._osv_scanner(data, "osv-x.json")
        self.assertEqual([(f["id"], f["fixed"]) for f in res.findings], [("CVE-2021-23337", "4.17.21")])
        self.assertIn("malformed OSV-Scanner", " ".join(res.warnings))

    def test_wrong_typed_nvd_response_warns_not_crash(self):
        self.assertEqual(nvd._parse({"vulnerabilities": [{"cve": {"metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": "nope", "version": "3.1"}}]},
            "references": []}}]}),
            {"cvss": None, "version": None, "exploit_ref": False, "found": True})
        self.assertEqual(nvd._parse({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": ["oops"]},
                                                           "references": []}}]}),
                         {"cvss": None, "version": None, "exploit_ref": False, "found": True})
        self.assertEqual(nvd._parse(["not-a-dict"]),
                         {"cvss": None, "version": None, "exploit_ref": False, "found": False})

    def test_malformed_report_in_scan_is_a_warning(self):
        (self.root / "trivy-x.json").write_text(json.dumps({
            "SchemaVersion": 2, "ArtifactName": "img", "Results": [
                {"Type": "npm", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-0001", "PkgName": "lodash", "InstalledVersion": "4.17.15",
                     "CVSS": {"nvd": {"V3Score": "high"}}},
                    {"VulnerabilityID": "CVE-2026-0002", "PkgName": "lodash", "InstalledVersion": "4.17.15",
                     "CVSS": {"nvd": {"V3Score": 9.8}}, "FixedVersion": "4.17.21"},
                ]},
            ]}))
        rec = scan.scan(str(self.root), offline=True, use_nvd=False)
        text = " ".join(rec["warnings"])
        self.assertIn("ignoring non-numeric CVSS score", text)
        self.assertEqual({(f["id"], f["cvss"]) for f in rec["items"]},
                         {("CVE-2026-0001", None), ("CVE-2026-0002", 9.8)})

    def test_osv_pagination_repeating_token_stops(self):
        calls = []

        def fake(url, payload=None, headers=None, timeout=30):
            calls.append(payload.get("page_token"))
            return {"vulns": [{"id": "CVE-2026-0001"}], "next_page_token": "t1"}

        with unittest.mock.patch.object(osv.net, "fetch_json", side_effect=fake):
            ids, warn = osv._query_pages("lodash", "npm", "4.17.15", "t1")
        self.assertEqual(ids, ["CVE-2026-0001"])
        self.assertIn("repeated a page token", warn)
        self.assertEqual(len(calls), 1)

    def test_osv_pagination_page_cap(self):
        n = [0]

        def fake(url, payload=None, headers=None, timeout=30):
            n[0] += 1
            return {"vulns": [], "next_page_token": f"t{n[0]}"}

        with unittest.mock.patch.object(osv.net, "fetch_json", side_effect=fake):
            ids, warn = osv._query_pages("lodash", "npm", "4.17.15", "t0")
        self.assertEqual(ids, [])
        self.assertIn(f"exceeded {osv.MAX_PAGES} pages", warn)
        self.assertEqual(n[0], osv.MAX_PAGES)

    def test_osv_non_object_feed_response_is_an_error_not_a_crash(self):
        with unittest.mock.patch.object(osv.net, "fetch_json", return_value=["not", "a", "dict"]):
            res, st = osv.lookup([{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}])
        self.assertEqual(res, {})
        self.assertIn("non-object", st.error)

    def test_malformed_recheck_date_does_not_crash_ranking(self):
        it = new_finding(id="CVE-2026-0001", package="lodash", installed="4.17.15", fixed="4.17.21",
                         ecosystem="npm")
        ranked = rank.rank([it], decisions={"CVE-2026-0001": {"status": "deferred", "reason": "later",
                                                               "recheck": "not-a-date", "package": None}},
                           today="2026-11-10")
        self.assertEqual(ranked[0]["status"], "defer_expired")  # bad date = treated as no usable date

    def test_serve_rejects_out_of_range_port(self):
        for bad in (0, 80, 70000, "abc"):
            self.assertEqual(cli.cmd_serve(SimpleNamespace(port=bad)), 2)

    def test_oversize_report_is_refused(self):
        (self.root / "trivy-x.json").write_text('{"SchemaVersion": 2, "Results": []}')
        with unittest.mock.patch.object(discovery, "MAX_REPORT_BYTES", 10):
            self.assertEqual(discovery.sniff_report(self.root / "trivy-x.json"), (None, None))
            with self.assertRaises(imports.ReportError) as cm:
                imports.load(self.root / "trivy-x.json")
            self.assertIn("larger than", str(cm.exception))

    def test_malformed_or_oversize_queue_json_is_refused(self):
        (state.path()).write_text("[1, 2, 3]")
        with self.assertRaises(state.StateError):
            state.load()
        with unittest.mock.patch.object(state, "MAX_BYTES", 10):
            (state.path()).write_text('{"schema": 1, "scans": {}, "decisions": {}}')
            with self.assertRaises(state.StateError) as cm:
                state.load()
            self.assertIn("larger than", str(cm.exception))


class HtmlEscapingFuzz(IsolatedTest):
    """Put a payload in every field a feed, report, lockfile, config or decision can control."""
    P = "<x id=pwn>'\""

    def test_every_page_escapes_every_field(self):
        P = self.P
        data = state.load()
        f = new_finding(id="CVE-2026-0001", aliases=[P], package=P, installed=P, fixed=P, ecosystem=P, summary=P,
                        url="https://e/" + P, epss=0.5, cvss=9.0,
                        kev={"date_added": P, "due_date": P, "ransomware": True, "action": P},
                        locations=[{"file": P, "system": P, "target": P, "image": P, "dir": P, "kind": P}])
        state.record_scan(data, {"root": P, "label": P, "scanned_at": P, "items": [f], "warnings": [P],
                                 "sources": {"OSV": {"as_of": P, "error": P, "note": P}}, "inventory": {}})
        state.set_decision(data, "CVE-2026-0001", "not_affected", reason=P)
        data["last_run"] = {"finished": P, "trigger": P, "targets": [P], "errors": [P]}
        state.save(data)
        httpd = web.make_server(0)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        for path in ("/", "/?view=cve", "/settings", "/?msg=" + urllib.request.quote(P)):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
            body = urllib.request.urlopen(req, timeout=5).read().decode()
            self.assertNotIn("<x id=pwn>", body, path)


class NetworkHardeningTests(unittest.TestCase):
    def test_redirects_must_stay_https(self):
        h = net._HttpsOnlyRedirects()
        req = urllib.request.Request("https://api.osv.dev/x")
        for bad in ("http://evil/x", "file:///etc/passwd", "ftp://x/y"):
            with self.assertRaises(urllib.error.URLError):
                h.redirect_request(req, None, 302, "", {}, bad)
        self.assertIsNotNone(h.redirect_request(req, None, 302, "", {}, "https://api.osv.dev/y"))


class UnitFileSafetyTests(unittest.TestCase):
    def test_environment_line_quoting(self):
        with unittest.mock.patch.dict(os.environ, {"PATCHQ_HOME": '/h/a b/$x/%i/"q"'}):
            self.assertEqual(service._env_lines(), 'Environment="PATCHQ_HOME=/h/a b/$x/%%i/\\"q\\""\n')
        with unittest.mock.patch.dict(os.environ, {"PATCHQ_HOME": "/h\nExecStartPre=/bin/sh -c evil"}):
            with self.assertRaises(service.ServiceError):
                service._env_lines()


if __name__ == "__main__":
    unittest.main()
