import base64
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

import import_phone_key as importer


WIRE = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
KEY = "ssh-ed25519 " + base64.b64encode(WIRE).decode("ascii") + " phone\n"


class FakeRunner:
    def __init__(self, *, devices="List of devices attached\nserial\tdevice\n"):
        self.devices = devices
        self.calls = []
        self.pulled = KEY
        self.phase2_key = None

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv == ("adb", "devices"):
            return subprocess.CompletedProcess(argv, 0, self.devices, "")
        if argv[:2] == ("adb", "pull"):
            Path(argv[3]).write_text(self.pulled, encoding="ascii")
        if argv[:2] == ("sudo", "python3"):
            self.phase2_key = Path(argv[5]).read_text(encoding="ascii")
            return subprocess.CompletedProcess(argv, 0, "Phase 2 done\n", "")
        if argv[:2] == ("ssh-keygen", "-lf"):
            self.phase2_key = Path(argv[2]).read_text(encoding="ascii")
            return subprocess.CompletedProcess(argv, 0, "256 SHA256:example phone (ED25519)\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class ImportTests(unittest.TestCase):
    def run_main(self, argv, runner=None, answer="y"):
        runner = runner or FakeRunner()
        out, err = io.StringIO(), io.StringIO()
        code = importer.main(argv, runner=runner, input_fn=lambda _: answer, out=out, err=err)
        return code, out.getvalue(), err.getvalue(), runner

    def test_pull_validate_install_and_cleanup(self):
        code, output, error, fake = self.run_main(["--yes", "--label", "pixel"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(fake.calls[0], ("adb", "devices"))
        self.assertEqual(fake.calls[1][:3], ("adb", "pull", importer.DEFAULT_REMOTE))
        self.assertIn("SHA256:example", output)
        self.assertEqual(fake.phase2_key, KEY)
        sudo = next(call for call in fake.calls if call[:2] == ("sudo", "python3"))
        self.assertEqual(sudo[2], str(Path(importer.__file__).resolve().parent / "phase2_ssh.py"))
        self.assertEqual(sudo[-2:], ("--label", "pixel"))
        self.assertFalse(Path(sudo[5]).exists())

    def test_local_file_dry_run_and_no_install(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phone.pub"
            path.write_text(KEY, encoding="ascii")
            code, output, error, fake = self.run_main(["--file", str(path), "--dry-run"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0][:2], ("ssh-keygen", "-lf"))
        self.assertIn("sudo python3", output)

    def test_declined_install(self):
        code, output, _, fake = self.run_main([], answer="n")
        self.assertEqual(code, 0)
        self.assertIn("Cancelled", output)
        self.assertFalse(any(call[0] == "sudo" for call in fake.calls))

    def test_delete_remote_after_success_only(self):
        code, _, _, fake = self.run_main(["--yes", "--delete-remote"])
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls[-1], ("adb", "shell", "rm", "--", importer.DEFAULT_REMOTE))
        fake = FakeRunner()
        # Declining the install must leave the remote file untouched.
        self.run_main(["--delete-remote"], runner=fake, answer="n")
        self.assertFalse(any(call[:3] == ("adb", "shell", "rm") for call in fake.calls))

    def test_device_errors(self):
        for devices, expected in [
            ("List of devices attached\n", "No adb device"),
            ("List of devices attached\nserial\tunauthorized\n", "USB debugging prompt"),
            ("List of devices attached\na\tdevice\nb\tdevice\n", "Multiple adb devices"),
        ]:
            with self.subTest(devices=devices):
                code, _, error, fake = self.run_main([], runner=FakeRunner(devices=devices))
                self.assertEqual(code, 1)
                self.assertIn(expected, error)
                self.assertEqual(fake.calls, [("adb", "devices")])

    def test_reject_malformed_or_private_keys_before_fingerprint(self):
        bad_keys = [
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            KEY + "\n",
            KEY + KEY,
            "ssh-rsa " + KEY.split()[1] + "\n",
            "ssh-ed25519 !!!\n",
            "ssh-ed25519 " + base64.b64encode(WIRE[:-1]).decode() + "\n",
            "ssh-ed25519 " + base64.b64encode(WIRE[:15] + b"\x00\x00\x00\x1f" + WIRE[19:]).decode() + "\n",
        ]
        for value in bad_keys:
            with self.subTest(value=value[:30]):
                fake = FakeRunner()
                fake.pulled = value
                code, _, error, fake = self.run_main(["--yes"], runner=fake)
                self.assertEqual(code, 1)
                self.assertIn("Phone key import failed", error)
                self.assertFalse(any(call[0] in ("ssh-keygen", "sudo") for call in fake.calls))

    def test_phase2_failure_does_not_delete_remote(self):
        fake = FakeRunner()
        # The runner sees the dynamic temp path, so fail every sudo command.
        original = fake.__call__

        def failing(argv):
            if argv[:2] == ["sudo", "python3"]:
                return subprocess.CompletedProcess(argv, 1, "", "phase 2 failed")
            return original(argv)

        code, _, error, _ = self.run_main(["--yes", "--delete-remote"], runner=failing)
        self.assertEqual(code, 1)
        self.assertIn("phase 2 failed", error)
        self.assertFalse(any(call[:3] == ("adb", "shell", "rm") for call in fake.calls))


if __name__ == "__main__":
    unittest.main()
