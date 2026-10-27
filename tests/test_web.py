import http.client
import json
import threading
import time
import urllib.parse
from unittest import mock

from patchqueue import config, runner, state, web
from patchqueue.model import new_finding
from tests.helpers import IsolatedTest


class DashboardTests(IsolatedTest):
    def setUp(self):
        super().setUp()
        data = state.load()
        evil = new_finding(id="CVE-2026-0001", package="<img src=x onerror=alert(1)>", installed="1.0.0",
                           fixed="1.0.1", ecosystem="npm", summary="<script>alert('xss')</script>",
                           url="javascript:alert(1)", epss=0.5,
                           locations=[{"file": "package-lock.json", "system": "web", "kind": "npm-lock"}])
        good = new_finding(id="CVE-2026-0002", package="lodash", installed="4.17.15", fixed="4.17.21",
                           ecosystem="npm", kev={"date_added": "2026-01-01", "due_date": "2026-01-22"},
                           url="https://osv.dev/vulnerability/GHSA-x",
                           locations=[{"file": "package-lock.json", "system": "web", "kind": "npm-lock", "direct": True}])
        good2 = new_finding(id="CVE-2026-0003", package="lodash", installed="4.17.15", fixed="4.17.19",
                            ecosystem="npm", epss=0.02,
                            locations=[{"file": "package-lock.json", "system": "web", "kind": "npm-lock", "direct": True}])
        state.record_scan(data, {"root": "/x", "label": "/x", "scanned_at": "2026-10-26T00:00:00+00:00",
                                 "items": [evil, good, good2], "warnings": [], "sources": {}, "inventory": {}})
        state.save(data)
        self.httpd = web.make_server(0)
        self.port = self.httpd.server_address[1]
        self.token = self.httpd.patchq_token
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def req(self, method, path, form=None, headers=None, host=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        body = None
        if form is not None or raw is not None:
            body = raw if raw is not None else urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    def post(self, path, **form):
        form.setdefault("token", self.token)
        return self.req("POST", path, form, headers={"Origin": f"http://127.0.0.1:{self.port}",
                                                     "Sec-Fetch-Site": "same-origin"})

    # --- rendering
    def test_grouped_page(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("PATCH TODAY", body)
        self.assertIn("lodash", body)
        self.assertIn("clears all", body)  # 2 lodash CVEs, one upgrade
        self.assertIn("npm install lodash@4.17.21", body)
        self.assertIn("Scan now", body)
        self.assertIn("form-action 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("<script", body.lower().replace("&lt;script", ""))

    def test_cve_and_settings_pages(self):
        self.assertEqual(self.get("/?view=cve")[0], 200)
        status, _, body = self.get("/settings")
        self.assertEqual(status, 200)
        self.assertIn("Automatic scans", body)
        self.assertIn("ssh -N -L", body)

    def test_everything_escaped(self):
        for path in ("/", "/?view=cve"):
            _, _, body = self.get(path)
            self.assertNotIn("<script>alert", body)
            self.assertNotIn("<img src=x", body)
            self.assertNotIn('href="javascript:', body)

    def test_flash_message_is_escaped(self):
        _, _, body = self.get("/?msg=" + urllib.parse.quote("<b>hi</b>"))
        self.assertIn("&lt;b&gt;hi&lt;/b&gt;", body)

    # --- request validation
    def get(self, path, host=None):
        return self.req("GET", path, host=host)

    def test_dns_rebinding_blocked(self):
        self.assertEqual(self.get("/", host="evil.example:80")[0], 403)
        self.assertEqual(self.post_raw_host("evil.example:80")[0], 403)

    def post_raw_host(self, host):
        return self.req("POST", "/scan", {"token": self.token}, host=host)

    def test_csrf_protections(self):
        # no token
        self.assertEqual(self.req("POST", "/decide", {"id": "CVE-2026-0002", "action": "done"})[0], 403)
        # wrong token from our own (stale) page: friendly redirect, nothing changed
        status, h, _ = self.post("/decide", id="CVE-2026-0002", action="done", token="nope")
        self.assertEqual(status, 303)
        self.assertIn("err=1", h["Location"])
        # wrong token with no browser origin headers at all: hard refusal
        self.assertEqual(self.req("POST", "/decide", {"id": "CVE-2026-0002", "action": "done", "token": "nope"})[0], 403)
        # cross-origin with a valid-looking token
        s = self.req("POST", "/decide", {"id": "CVE-2026-0002", "action": "done", "token": self.token},
                     headers={"Origin": "https://evil.example"})[0]
        self.assertEqual(s, 403)
        s = self.req("POST", "/decide", {"id": "CVE-2026-0002", "action": "done", "token": self.token},
                     headers={"Sec-Fetch-Site": "cross-site"})[0]
        self.assertEqual(s, 403)
        # wrong content type / oversized
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/decide", body=json.dumps({"token": self.token}),
                  headers={"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"})
        self.assertEqual(c.getresponse().status, 415)
        self.assertEqual(self.req("POST", "/decide", raw="x=" + "a" * 9000)[0], 413)
        self.assertEqual(state.load()["decisions"], {})  # nothing got through

    def test_token_rendered_only_in_page(self):
        _, _, body = self.get("/")
        self.assertIn(self.token, body)
        _, _, api = self.get("/api/status")
        self.assertNotIn(self.token, api)

    # --- actions
    def test_decide_flow(self):
        status, headers, _ = self.post("/decide", id="CVE-2026-0002", action="ignore", reason="unused path")
        self.assertEqual(status, 303)
        self.assertIn("marked+not+affected", headers["Location"])
        dec = state.load()["decisions"]["CVE-2026-0002"]
        self.assertEqual((dec["status"], dec["reason"]), ("not_affected", "unused path"))
        _, _, body = self.get("/")
        self.assertIn("Put back in queue", body)
        self.post("/decide", id="CVE-2026-0002", action="reopen")
        dec = state.load()["decisions"]["CVE-2026-0002"]
        self.assertEqual(dec["status"], "reopened")
        self.assertEqual(dec["history"][0]["reason"], "unused path")
        _, _, body = self.get("/")
        self.assertIn("PATCH TODAY", body)
        self.assertRegex(body, r"PATCH TODAY <span class='n'>1 package")

    def test_decide_validation(self):
        _, h, _ = self.post("/decide", id="CVE-2026-0002", action="ignore", reason="")
        self.assertIn("err=1", h["Location"])
        _, h, _ = self.post("/decide", id="CVE-2026-0002", action="defer", reason="x", recheck="2001-01-01")
        self.assertIn("err=1", h["Location"])
        _, h, _ = self.post("/decide", id="$(id)", action="done")
        self.assertIn("err=1", h["Location"])
        _, h, _ = self.post("/decide", id="CVE-2026-0002", action="rm -rf")
        self.assertIn("err=1", h["Location"])
        _, h, _ = self.post("/decide", id="CVE-2026-0002", action="done", back="https://evil.example")
        self.assertTrue(h["Location"].startswith("/?"))  # no open redirect

    def test_schedule_validation_and_save(self):
        with mock.patch("patchqueue.service.set_schedule", return_value=["scheduled scans: daily at 07:15"]):
            _, h, _ = self.post("/schedule", freq="daily", time="25:99", weekday="Mon")
            self.assertIn("err=1", h["Location"])
            _, h, _ = self.post("/schedule", freq="hourly; rm", time="07:15", weekday="Mon")
            self.assertIn("err=1", h["Location"])
            _, h, _ = self.post("/schedule", freq="daily", time="07:15", weekday="Mon")
            self.assertNotIn("err=1", h["Location"])
        self.assertEqual(config.load()["schedule"], {"freq": "daily", "time": "07:15", "weekday": "Mon"})

    def test_scan_button_runs_in_background(self):
        config.save({**config.load(), "roots": ["/x"], "docker": False})
        started = threading.Event()

        def fake_run(targets, docker=False, log=None, trigger=None, **kw):
            started.set()
            log("scanning /x")
            time.sleep(0.3)
            return [], []

        with mock.patch.object(runner, "run", side_effect=fake_run):
            status, h, _ = self.post("/scan")
            self.assertEqual(status, 303)
            self.assertTrue(started.wait(2))
            _, _, body = self.get("/")
            self.assertIn("Scanning…", body)
            self.assertIn("http-equiv='refresh'", body)
            _, _, st = self.get("/api/status")
            self.assertTrue(json.loads(st)["running"])
            for _ in range(30):
                if not self.httpd.patchq_job.running:
                    break
                time.sleep(0.05)
        _, _, body = self.get("/")
        self.assertNotIn("http-equiv='refresh'", body)

    def test_scan_with_nothing_configured_says_so(self):
        with state.transaction() as data:
            data["scans"] = {}
        _, h, _ = self.post("/scan")
        self.assertIn("patchq+init", h["Location"])

    def test_binds_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")


class DefaultTargetsTests(IsolatedTest):
    def test_falls_back_to_previous_scans(self):
        data = {"scans": {"/a": {}, "docker://pi": {}}}
        self.assertEqual(web.default_targets(data), (["/a"], True))
        config.save({**config.load(), "roots": ["/b"], "docker": False})
        self.assertEqual(web.default_targets(data), (["/b"], False))
