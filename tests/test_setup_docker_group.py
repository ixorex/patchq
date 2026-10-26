"""v0.2: grouping, `patchq init`, services, running-container scans, config-driven scans."""
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

from patchqueue import cli, config, dockerscan, group, init, rank, runner, service, state
from patchqueue.model import new_finding
from tests.helpers import SAMPLE, IsolatedTest, seed_cache
from tests.test_cli_e2e import run

TODAY = "2026-10-26"


def f(id, fixed, epss=None, pkg="Django", installed="3.2.0", eco="PyPI", **kw):
    return new_finding(id=id, package=pkg, installed=installed, fixed=fixed, ecosystem=eco, epss=epss,
                       locations=[{"file": "api/requirements.txt", "system": "api", "kind": "requirements",
                                   "dir": "/srv/api"}], **kw)


class GroupTests(IsolatedTest):
    def test_one_action_per_package_with_upgrade_targets(self):
        items = [f("CVE-1", "3.2.14", 0.74), f("CVE-2", "3.2.25", 0.02), f("CVE-3", "4.2.26", 0.26),
                 f("CVE-4", "5.2.17", 0.011), f("CVE-5", None, 0.5),
                 f("CVE-6", "4.17.21", 0.2, pkg="lodash", installed="4.17.15", eco="npm")]
        groups, decided = group.group(rank.rank(items, today=TODAY))
        self.assertEqual([g["package"] for g in groups], ["Django", "lodash"])
        dj = groups[0]
        self.assertEqual((dj["count"], dj["tier"]), (5, 1))
        self.assertEqual([(t["version"], t["clears"], t["of"], t["breaks"]["kind"]) for t in dj["targets"]],
                         [("3.2.25", 2, 4, "patch"), ("5.2.17", 4, 4, "major")])  # same-major == same-minor here
        self.assertEqual(dj["no_fix"], ["CVE-5"])
        self.assertIn("pip install Django==3.2.25", dj["targets"][0]["fix_cmd"])
        self.assertEqual(decided, [])

    def test_decided_items_leave_the_group(self):
        items = [f("CVE-1", "3.2.14", 0.74), f("CVE-2", "3.2.25", 0.02)]
        dec = {"CVE-1": {"status": "not_affected", "reason": "x", "at": "2026-10-01"}}
        groups, decided = group.group(rank.rank(items, dec, today=TODAY))
        self.assertEqual(groups[0]["count"], 1)
        self.assertEqual([d["id"] for d in decided], ["CVE-1"])

    def test_cli_grouped_by_default_by_cve_on_request(self):
        seed_cache()
        sample = self.copy_sample()
        run("scan", str(sample), "--offline")
        _, out, _ = run("queue")
        self.assertIn("lodash 4.17.15  (npm) · 2 vulns", out)
        self.assertIn("clears all 2", out)
        _, out2, _ = run("queue", "--by-cve")
        self.assertIn("CVE-2020-8203  lodash 4.17.15 → 4.17.19", out2)


class ConfigScanTests(IsolatedTest):
    def test_scan_without_args_uses_config(self):
        seed_cache()
        sample = self.copy_sample()
        config.save({**config.load(), "roots": [str(sample)]})
        code, out, err = run("scan", "--offline", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["groups"][0]["package"], "openssl")
        self.assertEqual(state.load()["last_run"]["targets"], [str(sample)])

    def test_quiet_mode_for_timers(self):
        seed_cache()
        config.save({**config.load(), "roots": [str(self.copy_sample())]})
        code, out, _ = run("scan", "--offline", "--quiet", "--trigger", "timer")
        self.assertEqual((code, out), (0, ""))
        self.assertEqual(state.load()["last_run"]["trigger"], "timer")

    def test_concurrent_scan_refused(self):
        with state.scan_lock():
            code, _, err = run("scan", str(SAMPLE), "--offline")
        self.assertEqual(code, 3)
        self.assertIn("already running", err)

    def test_config_validation(self):
        cfg = config.load()
        for bad in ({"freq": "hourly"}, {"time": "7:5"}, {"time": "24:00"}, {"weekday": "Funday"}):
            with self.assertRaises(config.ConfigError):
                config.save({**cfg, "schedule": {**cfg["schedule"], **bad}})
        (self.home / "config.json").write_text('{"schedule": {"freq": "nonsense"}, "roots": [1, "/ok"]}')
        loaded = config.load()
        self.assertEqual(loaded["schedule"]["freq"], "off")
        self.assertEqual(loaded["roots"], ["/ok"])


class DockerTests(IsolatedTest):
    PS = "\n".join(json.dumps(r) for r in [
        {"Image": "pihole/pihole:2024.07.0", "Names": "pihole", "Ports": "0.0.0.0:53->53/tcp"},
        {"Image": "jellyfin/jellyfin:latest", "Names": "jellyfin", "Ports": ""},
        {"Image": "--evil-flag", "Names": "bad", "Ports": ""},
    ])

    def fake_run(self, args, **kw):
        if args[1] == "ps":
            return mock.Mock(returncode=0, stdout=self.PS, stderr="")
        out = Path(args[args.index("--output") + 1])
        img = args[-1]
        out.write_text(json.dumps({"SchemaVersion": 2, "ArtifactName": img, "ArtifactType": "container_image",
                                   "Results": [{"Target": "x (debian 12)", "Type": "debian", "Vulnerabilities": [
                                       {"VulnerabilityID": "CVE-2014-0160", "PkgName": "openssl",
                                        "InstalledVersion": "1.0.1e-2+deb7u4", "FixedVersion": "1.0.1e-2+deb7u5"}]}]}))
        self.trivy_calls.append(args)
        return mock.Mock(returncode=0, stdout="", stderr="")

    def setUp(self):
        super().setUp()
        self.trivy_calls = []
        which = {"docker": "/usr/bin/docker", "trivy": "/usr/bin/trivy"}
        self._w = mock.patch.object(dockerscan.shutil, "which", side_effect=lambda t: which.get(t))
        self._r = mock.patch.object(dockerscan.subprocess, "run", side_effect=self.fake_run)
        self._w.start()
        self._r.start()

    def tearDown(self):
        self._r.stop()
        self._w.stop()
        super().tearDown()

    def test_running_containers(self):
        cs, warns = dockerscan.running_containers()
        self.assertEqual([(c["name"], c["published"]) for c in cs], [("pihole", True), ("jellyfin", False)])
        self.assertTrue(any("unusual image" in w for w in warns))

    def test_scan_docker_end_to_end_and_report_cache(self):
        seed_cache()
        code, out, err = run("scan", "--docker", "--json", "--no-nvd")
        self.assertEqual(code, 0, err)
        q = json.loads(out)
        hb = next(i for i in q["items"] if i["id"] == "CVE-2014-0160")
        self.assertEqual(hb["tier"], 0)
        self.assertEqual({l["system"] for l in hb["locations"]}, {"pihole", "jellyfin"})
        self.assertEqual(len(self.trivy_calls), 2)
        self.assertNotIn("--evil-flag", [a for c in self.trivy_calls for a in c])
        warnings = " ".join(w for s in q["scans"] for w in s["warnings"])
        self.assertIn("'pihole' publishes ports", warnings)
        run("scan", "--docker", "--json", "--no-nvd")
        self.assertEqual(len(self.trivy_calls), 2)  # reports reused within 24h

    def test_permission_denied_is_explained(self):
        self._r.stop()
        with mock.patch.object(dockerscan.subprocess, "run",
                               return_value=mock.Mock(returncode=1, stdout="", stderr="permission denied while trying to connect")):
            cs, warns = dockerscan.running_containers()
        self._r.start()
        self.assertEqual(cs, [])
        self.assertIn("usermod -aG docker", warns[0])

    def test_trivy_missing_is_explained(self):
        self._w.stop()
        with mock.patch.object(dockerscan.shutil, "which", side_effect=lambda t: "/usr/bin/docker" if t == "docker" else None):
            reports, warns = dockerscan.trivy_reports(["nginx:1.25"])
        self._w.start()
        self.assertEqual(reports, {})
        self.assertIn("apt install trivy", warns[0])


class ServiceTests(IsolatedTest):
    def setUp(self):
        super().setUp()
        self.xdg = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.xdg)
        self._env2 = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.xdg), "USER": "kali"})
        self._env2.start()
        self.calls = []
        self._run = mock.patch.object(service, "_run", side_effect=lambda a, timeout=30: (self.calls.append(a) or (0, "")))
        self._run.start()
        self._which = mock.patch.object(service.shutil, "which", return_value="/usr/bin/systemctl")
        self._which.start()

    def tearDown(self):
        self._which.stop()
        self._run.stop()
        self._env2.stop()
        super().tearDown()

    def test_install_writes_units_and_enables(self):
        cfg = {**config.load(), "schedule": {"freq": "weekly", "time": "07:05", "weekday": "Sat"}, "port": 8765}
        msgs = service.install(cfg)
        d = self.xdg / "systemd" / "user"
        timer = (d / service.TIMER).read_text()
        self.assertIn("OnCalendar=Sat *-*-* 07:05:00", timer)
        self.assertIn("Persistent=true", timer)
        serve = (d / service.SERVE).read_text()
        self.assertIn("-m patchqueue serve --port 8765", serve)
        self.assertIn("PATCHQ_HOME=", serve)  # custom home carried into the service
        self.assertIn("scan --quiet --trigger timer", (d / service.SCAN).read_text())
        self.assertIn(["systemctl", "--user", "enable", "--now", service.SERVE], self.calls)
        self.assertIn(["systemctl", "--user", "enable", "--now", service.TIMER], self.calls)
        self.assertTrue(any("weekly, Sat 07:05" in m for m in msgs))

    def test_schedule_off_disables_timer(self):
        cfg = {**config.load(), "schedule": {"freq": "off", "time": "06:30", "weekday": "Mon"}}
        service.set_schedule(cfg)
        self.assertIn(["systemctl", "--user", "disable", "--now", service.TIMER], self.calls)

    def test_cron_fallback_when_no_systemd(self):
        self._which.stop()
        with mock.patch.object(service.shutil, "which", return_value=None):
            msgs = service.install({**config.load(), "schedule": {"freq": "daily", "time": "06:30", "weekday": "Mon"}})
        self._which.start()
        self.assertTrue(any("crontab -e" in m and "30 6 * * *" in m for m in msgs))

    def test_paths_with_spaces_are_quoted(self):
        with mock.patch.object(service.sys, "executable", "/home/me/my venv/bin/python"):
            self.assertTrue(service._exec("serve").startswith('"/home/me/my venv/bin/python"'))


class InitTests(IsolatedTest):
    def setUp(self):
        super().setUp()
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        for rel, text in (("stack/compose.yml", "services: {a: {image: nginx:1}}"),
                          ("stack/web/package-lock.json", "{}"),
                          ("projects/api/requirements.txt", "a==1"),
                          ("projects/api/tests/fixtures/requirements.txt", "a==1"),
                          ("empty/readme.md", "hi"),
                          (".hidden/requirements.txt", "a==1")):
            p = self.base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def test_find_candidates(self):
        found = dict(init.find_candidates([self.base]))
        self.assertEqual(sorted(p.name for p in found), ["projects", "stack"])
        self.assertEqual(found[self.base / "stack"], {"compose": 1, "npm-lock": 1})
        self.assertEqual(found[self.base / "projects"], {"requirements": 1})  # tests/fixtures skipped

    def test_wizard_end_to_end(self):
        answers = iter(["1", str(self.base / "empty"), "", "n", "weekly", "07:15", "fri", "y", "n"])
        out = []
        with mock.patch.object(init.dockerscan, "_runtime", return_value=("docker", "/usr/bin/docker")), \
             mock.patch.object(init.service, "install", return_value=["dashboard service: on"]), \
             mock.patch.object(init.service, "available", return_value=True):
            cfg = init.wizard(ask=lambda _p: next(answers), say=out.append, bases=[self.base])
        self.assertEqual(cfg["roots"], sorted([str(self.base / "empty"), str(self.base / "projects")]))
        self.assertFalse(cfg["docker"])
        self.assertEqual(cfg["schedule"], {"freq": "weekly", "time": "07:15", "weekday": "Fri"})
        self.assertEqual(config.load()["schedule"]["weekday"], "Fri")
        self.assertTrue(any("dashboard service: on" in line for line in out))

    def test_init_yes_noninteractive(self):
        seed_cache()
        sample = self.copy_sample()
        with mock.patch.object(service, "install", return_value=["ok"]):
            code, out, err = run("init", "--yes", "--path", str(sample), "--schedule", "daily", "--time", "05:45",
                                 "--no-scan")
        self.assertEqual(code, 0, err)
        cfg = config.load()
        self.assertEqual((cfg["roots"], cfg["schedule"]["time"]), ([str(sample)], "05:45"))
        with mock.patch.object(service, "install", return_value=["ok"]):
            code, _, err = run("init", "--yes", "--time", "99:00", "--no-scan")
        self.assertEqual(code, 2)
