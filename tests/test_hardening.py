"""Hostile-input hardening: everything a scanned repo or report controls must not hang,
crash, read outside the scan root, or reach the terminal / browser unescaped."""
import os
import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

from patchqueue import fixcmd, miniyaml, parsers, rank, render, scan, service, state, version, web
from patchqueue.model import new_finding
from patchqueue.parsers import docker as dk, npm as npmp, python as pyp
from patchqueue.sources import net
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
