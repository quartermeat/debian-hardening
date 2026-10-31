import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

import phase2_ssh as phase2


ED_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTestingOnly="


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.key_type = "ED25519"
        self.test_fails = False
        self.effective = self.good_effective()
        self.sockets = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"

    @staticmethod
    def good_effective():
        return ("listenaddress 127.0.0.1:22\npasswordauthentication no\n"
                "kbdinteractiveauthentication no\npermitrootlogin no\nallowusers quartermeat\n")

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("ssh-keygen", "-l", "-f"):
            return subprocess.CompletedProcess(argv, 0, f"256 SHA256:fake comment ({self.key_type})\n", "")
        if argv == ("sshd", "-t") and self.test_fails:
            return subprocess.CompletedProcess(argv, 1, "", "bad config")
        output = self.effective if argv == ("sshd", "-T") else self.sockets if argv == ("ss", "-ltn") else ""
        return subprocess.CompletedProcess(argv, 0, output, "")


class PhaseTwoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.home = root / "home"
        self.home.mkdir()
        self.config = root / "sshd_config"
        self.config.write_text("Include /etc/ssh/sshd_config.d/*.conf\nMatch User nobody\n", encoding="utf-8")
        self.drop_in = root / "10-hardening.conf"
        self.backup = root / "backup"
        self.fake = FakeRunner()
        self.output = io.StringIO()
        self.paths = dict(sshd_config=self.config, drop_in=self.drop_in, home=self.home,
                          uid=phase2.os.getuid(), gid=phase2.os.getgid(),
                          root_uid=phase2.os.getuid(), root_gid=phase2.os.getgid(),
                          backup_dir=self.backup)

    def hardener(self):
        return phase2.Hardener("quartermeat", runner=self.fake, out=self.output, **self.paths)

    def run_main(self, args, euid=0):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = phase2.main(args, runner=self.fake, euid=euid, out=self.output, **self.paths)
        return code, stderr.getvalue()

    def test_dry_run_makes_no_calls_or_writes(self):
        code, _ = self.run_main([] , euid=1000)
        self.assertEqual(code, 0)
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.drop_in.exists())
        self.assertIn("pkg install openssh", self.output.getvalue())

    def test_non_root_apply_refused(self):
        code, error = self.run_main(["--apply"], euid=1000)
        self.assertEqual(code, 2)
        self.assertIn("requires root", error)
        self.assertEqual(self.fake.calls, [])

    def test_non_ed25519_key_rejected(self):
        key = self.home / "key.pub"
        key.write_text(ED_KEY + "\n", encoding="utf-8")
        self.fake.key_type = "RSA"
        code, error = self.run_main(["--apply", "--add-key", str(key), "--label", "phone"])
        self.assertEqual(code, 1)
        self.assertIn("Only ed25519", error)
        self.assertFalse(self.drop_in.exists())

    def test_duplicate_key_skipped_and_second_run_skips_reload(self):
        key = self.home / "key.pub"
        key.write_text(ED_KEY + " original\n", encoding="utf-8")
        args = ["--apply", "--add-key", str(key), "--label", "phone"]
        self.assertEqual(self.run_main(args)[0], 0)
        self.assertEqual(self.run_main(args)[0], 0)
        self.assertEqual((self.home / ".ssh" / "authorized_keys").read_text().count("ssh-ed25519"), 1)
        self.assertIn("phone", (self.home / ".ssh" / "authorized_keys").read_text())
        self.assertEqual(self.fake.calls.count(("systemctl", "reload", "ssh")), 1)
        self.assertEqual(self.fake.calls.count(("sshd", "-t")), 1)

    def test_failed_sshd_test_restores_prior_config_without_reload(self):
        self.drop_in.write_text("Prior config\n", encoding="utf-8")
        self.fake.test_fails = True
        code, error = self.run_main(["--apply"])
        self.assertEqual(code, 1)
        self.assertIn("bad config", error)
        self.assertEqual(self.drop_in.read_text(), "Prior config\n")
        self.assertEqual((self.backup / "10-hardening.conf").read_text(), "Prior config\n")
        self.assertNotIn(("systemctl", "reload", "ssh"), self.fake.calls)

    def test_missing_include_stops_before_change(self):
        self.config.write_text("Match User nobody\nInclude /etc/ssh/sshd_config.d/*.conf\n")
        code, error = self.run_main(["--apply"])
        self.assertEqual(code, 1)
        self.assertIn("Include", error)
        self.assertEqual(self.fake.calls, [])
        self.assertFalse((self.home / ".ssh").exists())

    def test_effective_mismatch_fails(self):
        self.fake.effective = self.fake.good_effective().replace("passwordauthentication no", "passwordauthentication yes")
        code, error = self.run_main(["--apply"])
        self.assertEqual(code, 1)
        self.assertIn("sshd -T mismatch", error)

    def test_no_keys_warning_and_permissions(self):
        self.assertEqual(self.run_main(["--apply"])[0], 0)
        self.assertIn("No keys yet; SSH will refuse everyone until you add one.", self.output.getvalue())
        self.assertEqual((self.home / ".ssh").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.home / ".ssh" / "authorized_keys").stat().st_mode & 0o777, 0o600)

    def test_public_listener_fails(self):
        self.fake.sockets += "LISTEN 0 128 [::]:22 [::]:*\n"
        code, error = self.run_main(["--apply"])
        self.assertEqual(code, 1)
        self.assertIn("Public SSH listener", error)


if __name__ == "__main__":
    unittest.main()
