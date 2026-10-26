import unittest

from patchqueue.version import bump_kind, compare, normalize_ecosystem


def ordered(test, versions, eco):
    for a, b in zip(versions, versions[1:]):
        test.assertEqual(compare(a, b, eco), -1, f"{a} < {b} ({eco})")
        test.assertEqual(compare(b, a, eco), 1, f"{b} > {a} ({eco})")


class SemverTests(unittest.TestCase):
    def test_numeric_not_string(self):
        self.assertEqual(compare("1.10.0", "1.9.0", "npm"), 1)
        self.assertEqual(compare("4.17.21", "4.17.3", "npm"), 1)

    def test_prerelease_order(self):
        ordered(self, ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                       "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"], "npm")

    def test_v_prefix_and_build_metadata(self):
        self.assertEqual(compare("v1.2.3", "1.2.3", "npm"), 0)
        self.assertEqual(compare("=1.2.3", "1.2.3", "npm"), 0)
        self.assertEqual(compare("1.2.3+build.5", "1.2.3", "npm"), 0)
        self.assertEqual(compare("v2.0.0", "1.99.99", "Go"), 1)


class Pep440Tests(unittest.TestCase):
    def test_full_order(self):
        ordered(self, ["1.0.dev0", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1",
                       "1.0", "1.0.post1", "1.0.0.post2", "1.0.1", "1!0.5"], "PyPI")

    def test_equivalences(self):
        self.assertEqual(compare("1.0", "1.0.0", "PyPI"), 0)
        self.assertEqual(compare("v1.0", "1.0", "PyPI"), 0)
        self.assertEqual(compare("1.0.0.post1", "1.0-1", "PyPI"), 0)
        self.assertEqual(compare("1.0RC1", "1.0rc1", "PyPI"), 0)

    def test_post_release_beats_release(self):
        self.assertEqual(compare("1.0.0.post1", "1.0.0", "PyPI"), 1)
        self.assertEqual(compare("2.10.1", "2.10", "PyPI"), 1)

    def test_local_version(self):
        self.assertEqual(compare("1.0+local.1", "1.0", "PyPI"), 1)


class DistroTests(unittest.TestCase):
    def test_debian(self):
        ordered(self, ["1.0~rc1", "1.0", "1.0-1", "1.0-1+deb7u1", "1.0a", "1:0.5"], "Debian")
        self.assertEqual(compare("4.2+dfsg-0.1", "4.2+dfsg-0.1+deb7u1", "Debian"), -1)
        self.assertEqual(compare("1.0.1e-2+deb7u4", "1.0.1e-2+deb7u5", "Debian:7"), -1)

    def test_alpine(self):
        ordered(self, ["1.2.3_alpha1", "1.2.3_rc1", "1.2.3", "1.2.3-r1", "1.2.3_p1", "1.2.4"], "Alpine")

    def test_generic_fallback(self):
        self.assertEqual(compare("1.0.1f", "1.0.1", "unknown-eco"), 1)
        self.assertEqual(compare("1.0rc1", "1.0", "unknown-eco"), -1)
        self.assertEqual(compare("1.10", "1.9", "unknown-eco"), 1)
        # unparseable semver falls back instead of crashing
        self.assertEqual(compare("1.2.3.4", "1.2.3.5", "npm"), -1)


class BumpTests(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(bump_kind("4.17.15", "4.17.21", "npm"), "patch")
        self.assertEqual(bump_kind("2.10", "2.11.3", "PyPI"), "minor")
        self.assertEqual(bump_kind("2.10", "3.1.3", "PyPI"), "major")
        self.assertEqual(bump_kind("0.4.1", "0.5.0", "npm"), "major")  # 0.x minor is breaking
        self.assertEqual(bump_kind("v1.2.3", "v1.2.4", "Go"), "patch")
        self.assertEqual(bump_kind("1.0.1e-2+deb7u4", "1.0.1e-2+deb7u5", "Debian"), "patch")
        self.assertEqual(bump_kind("1.2.3", None, "npm"), "unknown")

    def test_ecosystem_names(self):
        self.assertEqual(normalize_ecosystem("Debian:12"), "Debian")
        self.assertEqual(normalize_ecosystem("pip"), "PyPI")
        self.assertEqual(normalize_ecosystem("node-pkg"), "npm")


if __name__ == "__main__":
    unittest.main()
