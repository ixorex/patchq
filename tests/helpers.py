"""Test helpers: isolated PATCHQ_HOME, network blocked by default, feed fixtures seeded into the cache."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patchqueue.sources import cache, net, osv

FIX = Path(__file__).parent / "fixtures"
FEEDS = FIX / "feeds"
SAMPLE = FIX / "sample-homelab"


def _no_network(url, *a, **kw):
    raise net.FetchError(f"network disabled in tests: {url}")


class IsolatedTest(unittest.TestCase):
    """Each test gets its own ~/.patchqueue and no network unless it patches net.fetch."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="patchq-test-"))
        self._env = mock.patch.dict(os.environ, {"PATCHQ_HOME": str(self.home), "NO_COLOR": "1"})
        self._env.start()
        self._net = mock.patch.object(net, "fetch", side_effect=_no_network)
        self._net.start()
        self._sleep = mock.patch.object(net, "RETRY_SLEEP", 0)
        self._sleep.start()

    def tearDown(self):
        self._sleep.stop()
        self._net.stop()
        self._env.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def copy_sample(self):
        dst = Path(tempfile.mkdtemp(prefix="patchq-sample-")) / "sample-homelab"
        shutil.copytree(SAMPLE, dst)
        self.addCleanup(shutil.rmtree, dst.parent, ignore_errors=True)
        return dst


def seed_cache(fetched=None):
    """Write the feed fixtures into the cache exactly as a live run would have."""
    fetched = fetched or cache.now_iso()
    pkgs = json.loads((FEEDS / "osv-packages.json").read_text())
    for k, ids in pkgs.items():
        eco, name, ver = k.split("|")
        cache.write_json(osv.pkg_cache_path(eco, name, ver), {"fetched": fetched, "ids": ids})
    for f in (FEEDS / "osv").glob("*.json"):
        r = json.loads(f.read_text())
        cache.write_json(osv.vuln_cache_path(r["id"]), {"fetched": fetched, "record": r})
    kev = json.loads((FEEDS / "kev.json").read_text())
    cache.write_json(cache.cache_dir() / "kev.json",
                     {"fetched": fetched, "catalog_version": kev["catalogVersion"], "data": kev})
    ep = json.loads((FEEDS / "epss.json").read_text())
    scores = {c: {"epss": v, "percentile": None, "date": fetched[:10], "fetched": fetched}
              for c, v in ep.items() if c.startswith("CVE-")}
    cache.write_json(cache.cache_dir() / "epss.json", {"scores": scores})


def osv_record(rid):
    return json.loads((FEEDS / "osv" / f"{rid}.json").read_text())
