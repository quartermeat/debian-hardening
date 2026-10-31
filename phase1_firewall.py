#!/usr/bin/env python3
"""Debian 13 Phase 1 firewall and security-update hardening."""

import argparse
import datetime
import ipaddress
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


PACKAGES = ("ufw", "unattended-upgrades", "apt-listchanges")
AUTO_UPGRADES = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
HARDENING_UPGRADES = (
    '#clear Unattended-Upgrade::Allowed-Origins;\n'
    '#clear Unattended-Upgrade::Origins-Pattern;\n'
    'Unattended-Upgrade::Origins-Pattern {\n'
    '    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";\n'
    '};\n'
    'Unattended-Upgrade::Automatic-Reboot "false";\n'
)
APT_DIR = Path("/etc/apt/apt.conf.d")
UFW_DEFAULT = Path("/etc/default/ufw")
UFW_DIR = Path("/etc/ufw")


class HardeningError(Exception):
    pass


def command_runner(argv):
    """Single gateway for external commands; callers can inject a fake."""
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def desired_rules(lan):
    specs = (
        ("1714:1764", "tcp", "KDE Connect"),
        ("1714:1764", "udp", "KDE Connect"),
        ("27031:27036", "udp", "Steam"),
        ("27036:27037", "tcp", "Steam"),
        ("57621", "tcp", "Spotify Connect"),
        ("57621", "udp", "Spotify Connect"),
        ("5353", "udp", "mDNS"),
    )
    return [
        ("ufw", "allow", "from", lan, "to", "any", "port", port,
         "proto", protocol, "comment", comment)
        for port, protocol, comment in specs
    ]


def parse_added_rules(output):
    """Read `ufw show added`; reject lines we cannot account for."""
    rules = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Added user rules") or line == "(None)":
            continue
        if not line.startswith("ufw "):
            raise HardeningError(f"Unrecognized ufw rule output: {line}")
        try:
            rules.append(tuple(shlex.split(line)))
        except ValueError as exc:
            raise HardeningError(f"Cannot parse ufw rule: {line}") from exc
    return rules


class Hardener:
    def __init__(self, lan, *, runner=command_runner, backup_dir=None, out=None):
        self.lan = lan
        self.runner = runner
        self.backup_dir = backup_dir or (
            Path("/root/hardening-backups") / datetime.date.today().isoformat() / "phase1"
        )
        self.out = out or sys.stdout
        self.backed_up = False
        self.log_path = self.backup_dir / "actions.log"

    def say(self, message):
        print(message, file=self.out)

    def log(self, message):
        self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.backup_dir.chmod(0o700)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(message + "\n")

    def run(self, argv, *, allow_failure=False):
        self.log("RUN " + shlex.join(argv))
        try:
            result = self.runner(list(argv))
        except FileNotFoundError as exc:
            raise HardeningError(f"Command not installed: {argv[0]}") from exc
        if result.returncode and not allow_failure:
            raise HardeningError(
                f"Command failed ({result.returncode}): {shlex.join(argv)}\n"
                f"{result.stderr.strip()}"
            )
        return result

    def backup(self):
        if self.backed_up:
            return
        self.log("BACKUP begin")
        for source in (UFW_DIR, APT_DIR / "20auto-upgrades", APT_DIR / "50unattended-upgrades", UFW_DEFAULT):
            if not source.exists():
                continue
            destination = self.backup_dir / source.relative_to("/")
            if destination.exists():
                continue  # Retain the earliest pre-change snapshot for this day.
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
            self.log(f"BACKUP {source} -> {destination}")
        for name, argv in (("iptables-save.txt", ["iptables-save"]),
                           ("nft-ruleset.txt", ["nft", "list", "ruleset"])):
            destination = self.backup_dir / name
            if not destination.exists():
                if shutil.which(argv[0]) is None:
                    self.log(f"SKIP {argv[0]}: not installed")
                    continue
                result = self.run(argv, allow_failure=True)
                content = result.stdout
                if result.stderr:
                    content += f"\n# stderr ({argv[0]} exit {result.returncode}):\n{result.stderr}"
                destination.write_text(content, encoding="utf-8")
                self.log(f"BACKUP {shlex.join(argv)} -> {destination}")
        self.backed_up = True

    def write_if_changed(self, path, content):
        if path.exists() and path.read_text(encoding="utf-8") == content:
            return
        self.backup()
        path.write_text(content, encoding="utf-8")
        self.log(f"WRITE {path}\n{content.rstrip()}")

    def apply(self, *, replace_rules=False):
        self.log("Phase 1 apply started")
        missing = []
        for package in PACKAGES:
            result = self.run(["dpkg-query", "-W", "-f=${Status}", package], allow_failure=True)
            if result.returncode or result.stdout.strip() != "install ok installed":
                missing.append(package)
        if missing:
            self.backup()
            self.run(["apt-get", "install", "-y", *missing])

        existing = parse_added_rules(self.run(["ufw", "show", "added"]).stdout)
        wanted = desired_rules(self.lan)
        unexpected = [rule for rule in existing if rule not in wanted]
        if unexpected:
            self.say("Unexpected existing UFW rules:")
            for rule in unexpected:
                self.say("  " + shlex.join(rule))
            if not replace_rules:
                raise HardeningError("Stopped; review rules or rerun with --replace-rules")
            self.backup()
            self.run(["ufw", "--force", "reset"])
            existing = []

        if UFW_DEFAULT.exists():
            current = UFW_DEFAULT.read_text(encoding="utf-8")
            lines = current.splitlines(keepends=True)
            found = False
            for index, line in enumerate(lines):
                if line.startswith("IPV6="):
                    lines[index] = "IPV6=yes\n"
                    found = True
            if not found:
                lines.append("IPV6=yes\n")
            self.write_if_changed(UFW_DEFAULT, "".join(lines))
        else:
            self.write_if_changed(UFW_DEFAULT, "IPV6=yes\n")

        status = self.run(["ufw", "status", "verbose"]).stdout.lower()
        for marker, argv in (
            ("deny (incoming)", ["ufw", "default", "deny", "incoming"]),
            ("allow (outgoing)", ["ufw", "default", "allow", "outgoing"]),
            ("deny (routed)", ["ufw", "default", "deny", "routed"]),
            ("logging: on (low)", ["ufw", "logging", "low"]),
        ):
            if marker not in status:
                self.backup()
                self.run(argv)
        for rule in wanted:
            if rule not in existing:
                self.backup()
                self.run(rule)
        if "status: active" not in status:
            self.backup()
            self.run(["ufw", "--force", "enable"])

        self.write_if_changed(APT_DIR / "20auto-upgrades", AUTO_UPGRADES)
        self.write_if_changed(APT_DIR / "52hardening-unattended", HARDENING_UPGRADES)
        timers = ["apt-daily.timer", "apt-daily-upgrade.timer"]
        for timer in timers:
            enabled = self.run(["systemctl", "is-enabled", timer], allow_failure=True)
            active = self.run(["systemctl", "is-active", timer], allow_failure=True)
            if enabled.stdout.strip() != "enabled" or active.stdout.strip() != "active":
                self.run(["systemctl", "enable", "--now", timer])

        verified = self.run(["ufw", "status", "verbose"]).stdout.lower()
        if "status: active" not in verified or "deny (incoming)" not in verified:
            raise HardeningError("UFW verification failed: expected active with incoming denied")
        dry = self.run(["unattended-upgrade", "--dry-run"], allow_failure=True)
        if dry.returncode:
            raise HardeningError(f"unattended-upgrade --dry-run failed ({dry.returncode}): {dry.stderr.strip()}")
        self.say("Verification passed: UFW active, incoming denied, unattended-upgrade dry run passed.")
        self.say(f"Backup: {self.backup_dir}")
        self.rollback()

    def rollback(self):
        self.say("Rollback:")
        self.say("  sudo ufw disable")
        self.say(f"  sudo cp -a {self.backup_dir}/etc/ufw/. /etc/ufw/  # if backed up")
        self.say(f"  sudo cp -a {self.backup_dir}/etc/default/ufw /etc/default/ufw  # if backed up")
        for name in ("20auto-upgrades", "50unattended-upgrades"):
            self.say(f"  sudo cp -a {self.backup_dir}/etc/apt/apt.conf.d/{name} /etc/apt/apt.conf.d/{name}  # if backed up")
        self.say("  sudo rm /etc/apt/apt.conf.d/52hardening-unattended")

    def dry_run(self, *, replace_rules=False):
        self.say("Dry run: commands and writes that may be needed (state is not inspected).")
        self.say(f"Backup directory: {self.backup_dir} (mode 0700)")
        for source in (UFW_DIR, APT_DIR / "20auto-upgrades", APT_DIR / "50unattended-upgrades", UFW_DEFAULT):
            self.say(f"BACKUP if present: {source} -> {self.backup_dir / source.relative_to('/')}")
        commands = [
            *(["dpkg-query", "-W", "-f=${Status}", p] for p in PACKAGES),
            ["apt-get", "install", "-y", *PACKAGES],
            ["iptables-save"], ["nft", "list", "ruleset"],
            ["ufw", "show", "added"], ["ufw", "status", "verbose"],
            *([["ufw", "--force", "reset"]] if replace_rules else []),
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "default", "deny", "routed"], ["ufw", "logging", "low"],
            *desired_rules(self.lan), ["ufw", "--force", "enable"],
            ["systemctl", "enable", "--now", "apt-daily.timer"],
            ["systemctl", "enable", "--now", "apt-daily-upgrade.timer"],
            ["ufw", "status", "verbose"], ["unattended-upgrade", "--dry-run"],
        ]
        for argv in commands:
            self.say("RUN if needed: " + shlex.join(argv))
        self.say(f"WRITE if needed: {UFW_DEFAULT}\nIPV6=yes (preserving other lines)")
        self.say(f"WRITE if needed: {APT_DIR / '20auto-upgrades'}\n{AUTO_UPGRADES.rstrip()}")
        self.say(f"WRITE if needed: {APT_DIR / '52hardening-unattended'}\n{HARDENING_UPGRADES.rstrip()}")
        self.rollback()


def main(argv=None, *, runner=command_runner, euid=None, out=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply changes (requires root)")
    parser.add_argument("--replace-rules", action="store_true", help="reset unexpected UFW rules after backup")
    parser.add_argument("--lan", default="192.168.1.0/24", metavar="CIDR")
    args = parser.parse_args(argv)
    try:
        network = ipaddress.ip_network(args.lan, strict=True)
        if network.version != 4:
            raise ValueError("LAN must be an IPv4 CIDR")
    except ValueError as exc:
        parser.error(f"invalid --lan: {exc}")
    output = out or sys.stdout
    if args.apply and (os.geteuid() if euid is None else euid) != 0:
        print("--apply requires root; run with sudo", file=sys.stderr)
        return 2
    hardener = Hardener(str(network), runner=runner, out=output)
    try:
        if args.apply:
            hardener.apply(replace_rules=args.replace_rules)
        else:
            hardener.dry_run(replace_rules=args.replace_rules)
    except (HardeningError, OSError) as exc:
        print(f"Phase 1 failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
