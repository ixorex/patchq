import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from patchqueue import discovery, gitops
from patchqueue.scan import scan
from tests.helpers import IsolatedTest, seed_cache


def touch(p, text="{}"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def test_finds_nested_lockfiles_and_skips_vendor_dirs(self):
        touch(self.root / "a" / "b" / "c" / "package-lock.json")
        touch(self.root / "a" / "b" / "c" / "package.json")            # shadowed by the lockfile
        touch(self.root / "a" / "b" / "c" / "node_modules" / "x" / "package-lock.json")
        touch(self.root / "svc" / "requirements" / "prod.txt", "a==1")
        touch(self.root / "svc" / "requirements-dev.txt", "a==1")
        touch(self.root / "deep" / "er" / "poetry.lock", "")
        touch(self.root / "ops" / "docker-compose.prod.yml", "services: {}")
        touch(self.root / "ops" / "Dockerfile", "FROM alpine:3.19")
        touch(self.root / ".venv" / "requirements.txt", "a==1")
        touch(self.root / "trivy-results.json", '{"SchemaVersion": 2, "ArtifactName": "x"}')
        touch(self.root / "notes-trivy.json", '{"something": "else"}')  # name matches, content doesn't
        d = discovery.discover(self.root)
        found = {(str(f.path.relative_to(self.root)), f.kind) for f in d.files}
        self.assertEqual(found, {
            ("a/b/c/package-lock.json", "npm-lock"),
            ("svc/requirements/prod.txt", "requirements"),
            ("svc/requirements-dev.txt", "requirements"),
            ("deep/er/poetry.lock", "poetry"),
            ("ops/docker-compose.prod.yml", "compose"),
            ("ops/Dockerfile", "dockerfile"),
        })
        self.assertEqual([p.name for p in d.reports], ["trivy-results.json"])

    def test_unsupported_files_are_reported_not_skipped(self):
        touch(self.root / "fe" / "yarn.lock", "")
        touch(self.root / "fe" / "package.json")
        touch(self.root / "rs" / "Cargo.lock", "")
        touch(self.root / "py" / "pyproject.toml", "")
        touch(self.root / "pe" / "Pipfile", "")
        d = discovery.discover(self.root)
        self.assertEqual(d.files, [])  # package.json next to yarn.lock is not double-reported
        names = sorted(p.name for p, _ in d.unsupported)
        self.assertEqual(names, ["Cargo.lock", "Pipfile", "pyproject.toml", "yarn.lock"])
        self.assertTrue(all(reason for _, reason in d.unsupported))

    def test_symlink_escaping_root_is_skipped(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside)
        touch(outside / "secret.txt", "id_rsa contents")
        (self.root / "requirements.txt").symlink_to(outside / "secret.txt")
        touch(self.root / "real" / "requirements.txt", "a==1")
        (self.root / "requirements-dev.txt").symlink_to(self.root / "real" / "requirements.txt")
        d = discovery.discover(self.root)
        names = sorted(str(f.path.relative_to(self.root)) for f in d.files)
        self.assertEqual(names, ["real/requirements.txt", "requirements-dev.txt"])  # in-root symlink ok
        self.assertTrue(any("outside the scanned folder" in r for _, r in d.unsupported))

    def test_single_file_target(self):
        touch(self.root / "requirements.txt", "a==1")
        d = discovery.discover(self.root / "requirements.txt")
        self.assertEqual([f.kind for f in d.files], ["requirements"])


class GitUrlTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertTrue(gitops.is_git_url("https://github.com/me/repo.git"))
        self.assertTrue(gitops.is_git_url("git@github.com:me/repo.git"))
        self.assertTrue(gitops.is_git_url("ssh://git@host/me/repo"))
        for bad in ("http://github.com/me/repo", "git://host/repo", "-oProxyCommand=evil",
                    "ext::sh -c touch% /tmp/pwned", "file:///etc", "./local"):
            self.assertFalse(gitops.is_git_url(bad), bad)

    def test_repo_dir_is_sanitized(self):
        d = gitops.repo_dir("https://github.com/../../etc/passwd", Path("/h"))
        self.assertEqual(d.parent, Path("/h/repos"))
        self.assertNotIn("..", d.name)


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class GitPullIntegrationTest(IsolatedTest):
    def git(self, *args, cwd):
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd,
                       check=True, capture_output=True)

    def test_scan_pull_picks_up_new_lockfile(self):
        seed_cache()
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        origin, work, other = tmp / "origin.git", tmp / "work", tmp / "other"
        self.git("init", "--bare", "-q", str(origin), cwd=tmp)
        self.git("clone", "-q", str(origin), str(work), cwd=tmp)
        self.git("clone", "-q", str(origin), str(other), cwd=tmp)
        (other / "requirements.txt").write_text("PyYAML==5.3\n")
        self.git("add", ".", cwd=other)
        self.git("commit", "-qm", "add reqs", cwd=other)
        self.git("push", "-q", "origin", "HEAD", cwd=other)

        rec = scan(str(work), offline=True, pull=False)
        self.assertEqual(rec["items"], [])  # not pulled yet: empty folder
        rec = scan(str(work), offline=True, pull=True)
        self.assertEqual([i["id"] for i in rec["items"]], ["CVE-2020-14343"])


if __name__ == "__main__":
    unittest.main()
