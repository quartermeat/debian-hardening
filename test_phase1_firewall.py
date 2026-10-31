import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import phase1_firewall as phase1


class FakeRunner:
    def __init__(self, *, added=None):
        self.calls = []
        self.added = list(added or [])
        self.status = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[0] == "dpkg-query":
            return subprocess.CompletedProcess(argv, 0, "install ok installed", "")
        if argv == ("ufw", "show", "added"):
            lines = ["Added user rules (see 'ufw status' for running firewall):"]
            if self.added:
                lines.extend(phase1.shlex.join(rule) for rule in self.added)
            else:
                lines.append("(None)")
            return subprocess.CompletedProcess(argv, 0, "\n".join(lines), "")
        if argv == ("ufw", "status", "verbose"):
            return subprocess.CompletedProcess(argv, 0, self.status, "")
        if argv[:2] == ("systemctl", "is-enabled"):
            return subprocess.CompletedProcess(argv, 0, "enabled\n", "")
        if argv[:2] == ("systemctl", "is-active"):
            return subprocess.CompletedProcess(argv, 0, "active\n", "")
        if argv[:2] == ("ufw", "allow"):
            self.added.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")


class PhaseOneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        apt = root / "apt"
        apt.mkdir()
        ufw = root / "ufw"
        ufw.mkdir()
        default = root / "default-ufw"
        default.write_text("IPV6=yes\n", encoding="utf-8")
        self.backup = root / "backup"
        for name, value in (("APT_DIR", apt), ("UFW_DIR", ufw), ("UFW_DEFAULT", default)):
            patcher = patch.object(phase1, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.apt = apt

    def hardener(self, runner):
        return phase1.Hardener("192.168.1.0/24", runner=runner,
                               backup_dir=self.backup, out=io.StringIO())

    def test_dry_run_does_not_call_runner_or_write(self):
        fake = FakeRunner()
        output = io.StringIO()
        code = phase1.main([], runner=fake, euid=1000, out=output)
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls, [])
        self.assertIn("1714:1764", output.getvalue())
        self.assertIn("52hardening-unattended", output.getvalue())
        self.assertFalse(self.backup.exists())

    def test_apply_refuses_non_root(self):
        fake = FakeRunner()
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = phase1.main(["--apply"], runner=fake, euid=1000)
        self.assertEqual(code, 2)
        self.assertIn("requires root", stderr.getvalue())
        self.assertEqual(fake.calls, [])

    def test_exact_rule_set(self):
        self.assertEqual(phase1.desired_rules("192.168.1.0/24"), [
            ("ufw", "allow", "from", "192.168.1.0/24", "to", "any", "port", port,
             "proto", proto, "comment", comment)
            for port, proto, comment in (
                ("1714:1764", "tcp", "KDE Connect"),
                ("1714:1764", "udp", "KDE Connect"),
                ("27031:27036", "udp", "Steam"),
                ("27036:27037", "tcp", "Steam"),
                ("57621", "tcp", "Spotify Connect"),
                ("57621", "udp", "Spotify Connect"),
                ("5353", "udp", "mDNS"),
            )
        ])

    def test_show_added_none_is_empty_and_other_unknown_lines_fail(self):
        output = "Added user rules (see 'ufw status' for running firewall):\n(None)\n"
        self.assertEqual(phase1.parse_added_rules(output), [])
        with self.assertRaisesRegex(phase1.HardeningError, "Unrecognized ufw rule output"):
            phase1.parse_added_rules(output.replace("(None)", "unexpected"))

    def test_matching_state_skips_mutations(self):
        (self.apt / "20auto-upgrades").write_text(phase1.AUTO_UPGRADES, encoding="utf-8")
        (self.apt / "52hardening-unattended").write_text(phase1.HARDENING_UPGRADES, encoding="utf-8")
        fake = FakeRunner(added=phase1.desired_rules("192.168.1.0/24"))
        hardener = self.hardener(fake)
        hardener.apply()
        hardener.apply()
        self.assertFalse(any(call[0] in ("apt-get", "iptables-save", "nft") for call in fake.calls))
        self.assertFalse(any(call[:2] == ("ufw", "allow") for call in fake.calls))
        self.assertFalse(any(call[:2] == ("ufw", "default") for call in fake.calls))
        self.assertFalse(any(call[:2] == ("systemctl", "enable") for call in fake.calls))
        self.assertFalse((self.backup / "iptables-save.txt").exists())

    def test_apply_adds_rules_and_writes_security_only_drop_in(self):
        fake = FakeRunner()
        with patch.object(phase1.shutil, "which", return_value="/usr/sbin/tool"):
            hardener = self.hardener(fake)
            hardener.apply()
            hardener.apply()
        self.assertEqual(fake.added, phase1.desired_rules("192.168.1.0/24"))
        self.assertEqual(sum(call[:2] == ("ufw", "allow") for call in fake.calls), 7)
        self.assertFalse(any(call[0] == "apt-get" for call in fake.calls))
        self.assertIn("#clear Unattended-Upgrade::Allowed-Origins;",
                      (self.apt / "52hardening-unattended").read_text(encoding="utf-8"))
        self.assertIn("codename=${distro_codename}-security",
                      (self.apt / "52hardening-unattended").read_text(encoding="utf-8"))
        self.assertTrue((self.backup / "actions.log").exists())
        self.assertTrue((self.backup / "iptables-save.txt").exists())

    def test_backup_skips_missing_binary_and_continues(self):
        fake = FakeRunner()
        with patch.object(phase1.shutil, "which", side_effect=lambda name: None if name == "iptables-save" else "/usr/sbin/nft"):
            self.hardener(fake).backup()
        self.assertNotIn(("iptables-save",), fake.calls)
        self.assertIn(("nft", "list", "ruleset"), fake.calls)
        self.assertFalse((self.backup / "iptables-save.txt").exists())
        self.assertTrue((self.backup / "nft-ruleset.txt").exists())
        self.assertIn("SKIP iptables-save: not installed", (self.backup / "actions.log").read_text(encoding="utf-8"))

    def test_backup_records_stderr_on_command_failure(self):
        def failing_runner(argv):
            return subprocess.CompletedProcess(argv, 4, "partial output\n", "permission denied\n")

        with patch.object(phase1.shutil, "which", return_value="/usr/sbin/tool"):
            self.hardener(failing_runner).backup()
        saved = (self.backup / "iptables-save.txt").read_text(encoding="utf-8")
        self.assertIn("partial output", saved)
        self.assertIn("permission denied", saved)
        self.assertIn("exit 4", saved)

    def test_run_reports_missing_command_as_hardening_error(self):
        def missing_runner(argv):
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        with self.assertRaisesRegex(phase1.HardeningError, "Command not installed: apt-get"):
            self.hardener(missing_runner).run(["apt-get", "install", "-y", "ufw"])

    def test_unexpected_rule_stops_before_firewall_change(self):
        extra = ("ufw", "allow", "1935")
        fake = FakeRunner(added=[extra])
        output = io.StringIO()
        hardener = phase1.Hardener("192.168.1.0/24", runner=fake,
                                   backup_dir=self.backup, out=output)
        with self.assertRaisesRegex(phase1.HardeningError, "Stopped"):
            hardener.apply()
        self.assertIn("1935", output.getvalue())
        self.assertFalse(any(call[:2] == ("ufw", "allow") for call in fake.calls))

    def test_bad_cidr_rejected(self):
        fake = FakeRunner()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                phase1.main(["--lan", "192.168.1.13/24"], runner=fake)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
