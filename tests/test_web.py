import http.client
import json
import threading

from patchqueue import state, web
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
                           locations=[{"file": "package-lock.json", "system": "web", "kind": "npm-lock", "direct": True}])
        state.record_scan(data, {"root": "/x", "label": "/x", "scanned_at": "2026-10-26T00:00:00+00:00",
                                 "items": [evil, good], "warnings": [], "sources": {}, "inventory": {}})
        state.save(data)
        self.httpd = web.make_server(0)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def get(self, path, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers={"Host": host or f"127.0.0.1:{self.port}"})
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    def test_page_same_ranking_as_cli(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("PATCH TODAY", body)
        self.assertLess(body.index("CVE-2026-0002"), body.index("CVE-2026-0001"))  # KEV first
        self.assertIn("npm install lodash@4.17.21", body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_everything_escaped(self):
        _, _, body = self.get("/")
        self.assertNotIn("<script>alert", body)
        self.assertNotIn("<img src=x", body)
        self.assertNotIn('href="javascript:', body)
        self.assertIn("&lt;script&gt;", body)

    def test_dns_rebinding_blocked(self):
        status, _, _ = self.get("/", host="evil.example:80")
        self.assertEqual(status, 403)

    def test_api_and_read_only(self):
        status, _, body = self.get("/api/queue")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["items"][0]["id"], "CVE-2026-0002")
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/", body="x", headers={"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(c.getresponse().status, 405)

    def test_binds_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")
