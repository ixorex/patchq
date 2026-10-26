import shutil
import tempfile
import unittest
from pathlib import Path

from patchqueue import miniyaml, parsers
from tests.helpers import FIX, SAMPLE

P = FIX / "parsers"


def by_name(res):
    return {p["name"]: p for p in res.packages}


class NpmTests(unittest.TestCase):
    def test_lockfile_v3_direct_transitive_dev(self):
        res = parsers.parse(SAMPLE / "web" / "package-lock.json", "npm-lock")
        pk = by_name(res)
        self.assertEqual(pk["lodash"]["version"], "4.17.15")
        self.assertTrue(pk["lodash"]["direct"])
        self.assertFalse(pk["minimist"]["direct"])  # pulled in by mkdirp
        self.assertEqual(len(res.packages), 3)
        self.assertEqual(res.warnings, [])

    def test_lockfile_v1_with_nested_and_git_deps(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        shutil.copy(P / "lockfile-v1.json", d / "package-lock.json")
        shutil.copy(P / "package-v1.json", d / "package.json")
        res = parsers.parse(d / "package-lock.json", "npm-lock")
        got = {(p["name"], p["version"]): p for p in res.packages}
        self.assertIn(("qs", "6.5.1"), got)  # nested copy
        self.assertIn(("qs", "6.5.2"), got)  # hoisted copy
        self.assertTrue(got[("express", "4.16.0")]["direct"])
        self.assertFalse(got[("qs", "6.5.2")]["direct"])
        self.assertTrue(got[("mocha", "5.0.0")]["dev"])
        self.assertTrue(any("non-registry" in w for w in res.warnings))

    def test_package_json_only_is_flagged_approximate(self):
        res = parsers.parse(P / "package-nolock.json", "npm-manifest")
        pk = by_name(res)
        self.assertEqual(pk["lodash"]["version"], "4.17.15")
        self.assertTrue(pk["lodash"]["approx"])
        self.assertFalse(pk["axios"]["approx"])
        self.assertEqual(pk["jest"]["version"], "29.0.0")
        self.assertNotIn("left", pk)
        self.assertTrue(any("approximate" in w for w in res.warnings))
        self.assertTrue(any("can't pin" in w for w in res.warnings))

    def test_garbage_file_becomes_warning_not_crash(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "package-lock.json").write_text("{not json")
        res = parsers.parse(d / "package-lock.json", "npm-lock")
        self.assertEqual(res.packages, [])
        self.assertIn("NOT checked", res.warnings[0])


class PythonTests(unittest.TestCase):
    def test_requirements_pins_markers_hashes_unpinned(self):
        res = parsers.parse(SAMPLE / "api" / "requirements.txt", "requirements")
        pk = by_name(res)
        self.assertEqual(pk["Django"]["version"], "3.2.0")
        self.assertEqual(pk["jinja2"]["version"], "2.10")
        self.assertEqual(pk["PyYAML"]["version"], "5.3")  # marker + hash continuation
        self.assertNotIn("requests", pk)
        self.assertTrue(any("unpinned" in w and "requests" in w for w in res.warnings))
        self.assertTrue(any("editable" in w for w in res.warnings))

    def test_requirements_includes_extras_wildcards(self):
        res = parsers.parse(P / "requirements-incl.txt", "requirements")
        pk = by_name(res)
        self.assertEqual(pk["click"]["version"], "8.0.0")       # followed -r base.txt
        self.assertTrue(pk["click"]["file_abs"].endswith("base.txt"))
        self.assertNotIn("flask", pk)                           # requirements-*.txt is discovered separately
        self.assertEqual(pk["werkzeug"]["version"], "2.0.0")    # extras
        self.assertNotIn("foo", pk)                             # 1.* is not a pin
        self.assertTrue(any("foo==1.*" in w for w in res.warnings))

    def test_poetry_lock(self):
        res = parsers.parse(SAMPLE / "worker" / "poetry.lock", "poetry")
        pk = by_name(res)
        self.assertEqual(pk["certifi"]["version"], "2022.12.7")
        self.assertTrue(pk["pytest"]["dev"])
        self.assertFalse(pk["jinja2"]["dev"])

    def test_poetry_fallback_parser_matches_tomllib(self):
        from patchqueue.parsers.python import _toml_packages_fallback
        text = (SAMPLE / "worker" / "poetry.lock").read_text()
        got = _toml_packages_fallback(text)
        self.assertEqual([(p["name"], p["version"]) for p in got],
                         [("certifi", "2022.12.7"), ("jinja2", "2.10"), ("pytest", "7.4.0")])
        self.assertEqual(got[2]["groups"], ["dev"])

    def test_pipfile_lock(self):
        res = parsers.parse(P / "Pipfile.lock", "pipenv")
        pk = by_name(res)
        self.assertEqual(pk["requests"]["version"], "2.25.0")
        self.assertTrue(pk["pytest"]["dev"])
        self.assertNotIn("mylib", pk)
        self.assertTrue(res.warnings)


class DockerTests(unittest.TestCase):
    def test_compose_services(self):
        res = parsers.parse(SAMPLE / "compose.yml", "compose")
        imgs = {i["service"]: i for i in res.images}
        self.assertEqual(imgs["proxy"]["image"], "nginx:1.25-alpine")
        self.assertTrue(imgs["proxy"]["published_ports"])
        self.assertEqual(imgs["legacy"]["image"], "example/legacy-shell:1.0")
        self.assertNotIn("app", imgs)
        self.assertTrue(any("built locally" in w for w in res.warnings))

    def test_compose_v1_quotes_vars_anchors_folded(self):
        res = parsers.parse(P / "compose-legacy.yml", "compose")
        imgs = {i["service"]: i for i in res.images}
        self.assertEqual(imgs["web"]["image"], "ghcr.io/me/web:2.1")
        self.assertTrue(imgs["db"]["unresolved"])
        self.assertEqual(imgs["cache"]["image"], "redis:7.2")
        self.assertEqual(len(res.images), 3)  # the commented-out image is ignored

    def test_dockerfile_from_lines(self):
        res = parsers.parse(P / "Dockerfile", "dockerfile")
        self.assertEqual([i["image"] for i in res.images], ["node:18-alpine", "python:3.11-slim-bookworm"])


class MiniYamlTests(unittest.TestCase):
    def test_subset(self):
        doc = miniyaml.loads("""
a: 1
b:
  - x
  - "y: z"
  - k: v
    k2: [1, 2]
c: {exposed: true, critical: no}
d: 'it''s'
e: http://example.com:8080/path  # comment
f:
- top-level-seq
""")
        self.assertEqual(doc["a"], "1")
        self.assertEqual(doc["b"][0], "x")
        self.assertEqual(doc["b"][1], "y: z")
        self.assertEqual(doc["b"][2], {"k": "v", "k2": ["1", "2"]})
        self.assertEqual(doc["c"], {"exposed": True, "critical": False})
        self.assertEqual(doc["d"], "it's")
        self.assertEqual(doc["e"], "http://example.com:8080/path")
        self.assertEqual(doc["f"], ["top-level-seq"])


if __name__ == "__main__":
    unittest.main()
