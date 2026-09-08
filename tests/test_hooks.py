"""Regression checks for staged-only repository hygiene hooks."""

import base64
import getpass
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class PreCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tunnel-hook-check-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        shutil.copytree(REPO / ".githooks", self.root / ".githooks")
        shutil.copy2(REPO / ".gitleaks.toml", self.root / ".gitleaks.toml")

    def stage(self, content, name="change.txt"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        subprocess.run(["git", "add", "--", name], cwd=self.root, check=True)
        return path

    def hook(self):
        return subprocess.run(
            ["sh", ".githooks/pre-commit"], cwd=self.root,
            capture_output=True, text=True,
        )

    def test_portable_content_passes(self):
        self.stage("Portable configuration.\n")
        self.assertEqual(self.hook().returncode, 0)

    def test_current_username_is_rejected(self):
        self.stage("Account: " + getpass.getuser() + "\n")
        self.assertNotEqual(self.hook().returncode, 0)

    def test_current_home_is_rejected(self):
        self.stage(str(Path.home() / "private-settings") + "\n")
        self.assertNotEqual(self.hook().returncode, 0)

    def test_other_accounts_on_all_platforms_are_rejected(self):
        for prefix in ["/" + "Users/", "/" + "home/", "C:/" + "Users/", "C:" + "\\" + "Users" + "\\"]:
            with self.subTest(prefix=prefix):
                self.stage(prefix + "nonplaceholderaccount/private-settings\n")
                self.assertNotEqual(self.hook().returncode, 0)

    def test_documentation_placeholder_passes(self):
        self.stage("/" + "home/example/project\n")
        self.assertEqual(self.hook().returncode, 0)

    def test_unstaged_disclosure_is_not_part_of_the_commit(self):
        path = self.stage("Portable configuration.\n")
        path.write_text(str(Path.home() / "private-settings") + "\n")
        self.assertEqual(self.hook().returncode, 0)

    def test_secret_like_value_is_rejected(self):
        # Synthetic scanner fixture, never an issued credential.
        token = "gh" + "p_" + "7Zm9Wq2Rt4Yu6Io8Pa0Sd3Fg5Hj1Kl9Xc2Vb"
        self.stage("credential = " + token + "\n")
        result = self.hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gitleaks", result.stderr)
        self.assertNotIn(token, result.stderr)

    def test_new_key_in_test_support_is_not_exempt(self):
        delimiter = "-" * 5
        key = (
            delimiter + "BEGIN OPENSSH PRIVATE KEY" + delimiter + "\n"
            + base64.b64encode(bytes(range(128))).decode() + "\n"
            + delimiter + "END OPENSSH PRIVATE KEY" + delimiter + "\n"
        )
        self.stage(key, "src/test_support.rs")
        result = self.hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gitleaks", result.stderr)

    def test_existing_public_fixture_keys_pass(self):
        self.stage((REPO / "src/test_support.rs").read_text(), "src/test_support.rs")
        self.assertEqual(self.hook().returncode, 0)


if __name__ == "__main__":
    unittest.main()
