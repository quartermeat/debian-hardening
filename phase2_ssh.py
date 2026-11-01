#!/usr/bin/env python3
"""Debian 13 Phase 2: key-only SSH bound to localhost."""

import argparse
import datetime
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import sys


SSHD_CONFIG = Path("/etc/ssh/sshd_config")
DROP_IN = Path("/etc/ssh/sshd_config.d/10-hardening.conf")
BACKUP_ROOT = Path("/root/hardening-backups")
KEY_PATTERN = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?:\s+.*)?$")


class HardeningError(Exception):
    pass


def command_runner(argv):
    """Single gateway for external commands; tests can inject a fake."""
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def desired_config(user):
    return ("ListenAddress 127.0.0.1\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "PermitRootLogin no\n"
            f"AllowUsers {user}\n"
            "X11Forwarding no\n"
            "MaxAuthTries 3\n"
            "ChannelTimeout session=10m\n"
            "UnusedConnectionTimeout 1m\n"
            "ClientAliveInterval 60\n"
            "ClientAliveCountMax 3\n")


def has_early_include(content):
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        if words[0].lower() == "match":
            return False
        if (words[0].lower() == "include" and
                "/etc/ssh/sshd_config.d/*.conf" in words[1:]):
            return True
    return False


def key_identity(line):
    match = KEY_PATTERN.fullmatch(line.strip())
    return ("ssh-ed25519", match.group(1)) if match else None


class Hardener:
    def __init__(self, user, *, runner=command_runner, backup_dir=None, out=None,
                 sshd_config=SSHD_CONFIG, drop_in=DROP_IN, home=None, uid=None, gid=None,
                 root_uid=0, root_gid=0):
        self.user = user
        self.runner = runner
        self.backup_dir = backup_dir or (BACKUP_ROOT / datetime.date.today().isoformat() / "phase2")
        self.out = out or sys.stdout
        self.sshd_config = Path(sshd_config)
        self.drop_in = Path(drop_in)
        self.home = Path(home) if home is not None else None
        self.uid = uid
        self.gid = gid
        self.root_uid = root_uid
        self.root_gid = root_gid
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
            raise HardeningError(f"Command failed ({result.returncode}): {shlex.join(argv)}\n"
                                 f"{result.stderr.strip()}")
        return result

    def resolve_user(self):
        if self.home is None or self.uid is None or self.gid is None:
            try:
                account = pwd.getpwnam(self.user)
            except KeyError as exc:
                raise HardeningError(f"Unknown user: {self.user}") from exc
            self.home = Path(account.pw_dir)
            self.uid = account.pw_uid
            self.gid = account.pw_gid

    def backup(self, path, name):
        destination = self.backup_dir / name
        if path.exists() and not destination.exists():
            self.log(f"BACKUP {path} -> {destination}")
            shutil.copy2(path, destination)
        return destination

    def validate_key(self, source, label):
        if not label or any(c in label for c in "\r\n\t") or label.strip() != label:
            raise HardeningError("Key label must be nonempty, single-line text")
        result = self.run(["ssh-keygen", "-l", "-f", str(source)])
        if "(ED25519)" not in result.stdout:
            raise HardeningError(f"Only ed25519 keys are accepted: {source}")
        lines = [line.strip() for line in Path(source).read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(lines) != 1 or key_identity(lines[0]) is None:
            raise HardeningError(f"Expected one ssh-ed25519 public key in {source}")
        kind, blob = key_identity(lines[0])
        return kind, blob, f"{kind} {blob} {label}\n"

    def add_keys(self, keys):
        ssh_dir = self.home / ".ssh"
        authorized = ssh_dir / "authorized_keys"
        if ssh_dir.is_symlink() or authorized.is_symlink():
            raise HardeningError("Refusing symlink in SSH key path")
        old = authorized.read_text(encoding="utf-8") if authorized.exists() else ""
        present = {identity for line in old.splitlines() if (identity := key_identity(line))}
        additions = []
        for kind, blob, formatted in keys:
            if (kind, blob) not in present:
                additions.append(formatted)
                present.add((kind, blob))
        if not old.strip() and not additions:
            self.say("No keys yet; SSH will refuse everyone until you add one.")
        if not ssh_dir.exists():
            ssh_dir.mkdir(mode=0o700)
            self.log(f"MKDIR {ssh_dir}")
        if ssh_dir.stat().st_mode & 0o777 != 0o700 or (ssh_dir.stat().st_uid, ssh_dir.stat().st_gid) != (self.uid, self.gid):
            ssh_dir.chmod(0o700)
            os.chown(ssh_dir, self.uid, self.gid)
            self.log(f"CHMOD/CHOWN {ssh_dir}")
        if additions:
            self.backup(authorized, "authorized_keys")
            separator = "\n" if old and not old.endswith("\n") else ""
            authorized.write_text(old + separator + "".join(additions), encoding="utf-8")
            self.log(f"ADD {len(additions)} key(s) to {authorized}")
        elif not authorized.exists():
            authorized.touch(mode=0o600)
            self.log(f"CREATE {authorized}")
        if authorized.stat().st_mode & 0o777 != 0o600 or (authorized.stat().st_uid, authorized.stat().st_gid) != (self.uid, self.gid):
            self.backup(authorized, "authorized_keys")
            authorized.chmod(0o600)
            os.chown(authorized, self.uid, self.gid)
            self.log(f"CHMOD/CHOWN {authorized}")

    def verify(self):
        effective = self.run(["sshd", "-T"]).stdout
        values = {}
        for line in effective.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                values.setdefault(parts[0].lower(), []).append(parts[1].strip().lower())
        expected = {"listenaddress": ["127.0.0.1:22"],
                    "passwordauthentication": ["no"],
                    "kbdinteractiveauthentication": ["no"],
                    "permitrootlogin": ["no"],
                    "allowusers": [self.user.lower()],
                    "unusedconnectiontimeout": ["60", "1m"],
                    "clientaliveinterval": ["60"],
                    "clientalivecountmax": ["3"]}
        for setting, wanted in expected.items():
            actual = values.get(setting)
            if actual is None or len(actual) != 1 or actual[0] not in wanted:
                raise HardeningError(f"sshd -T mismatch: {setting}: {values.get(setting)} (expected {wanted})")
        channel_values = values.get("channeltimeout", [])
        sessions = [token.split("=", 1)[1] for value in channel_values
                    for token in value.split() if token.startswith("session=")]
        if len(sessions) != 1 or sessions[0] not in ("600", "10m"):
            raise HardeningError(f"sshd -T mismatch: channeltimeout: {channel_values} (expected session=10m)")
        sockets = self.run(["ss", "-ltn"]).stdout
        for line in sockets.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3].lower()
            if local in ("0.0.0.0:22", "[::]:22", "*:22", ":::22"):
                raise HardeningError(f"Public SSH listener remains: {local}")
        self.say("Verification passed: SSH is key-only, idle timeouts are set, and it listens on localhost only.")

    def apply(self, key_specs):
        self.resolve_user()
        if not has_early_include(self.sshd_config.read_text(encoding="utf-8")):
            raise HardeningError("sshd_config must Include /etc/ssh/sshd_config.d/*.conf before the first Match")
        if self.drop_in.is_symlink():
            raise HardeningError("Refusing symlink at SSH drop-in")
        keys = [self.validate_key(source, label) for source, label in key_specs]
        self.add_keys(keys)
        desired = desired_config(self.user)
        old = self.drop_in.read_bytes() if self.drop_in.exists() else None
        old_mode = self.drop_in.stat().st_mode & 0o777 if old is not None else None
        old_owner = (self.drop_in.stat().st_uid, self.drop_in.stat().st_gid) if old is not None else None
        changed = old != desired.encode() or (old is not None and
                    (old_mode != 0o644 or self.drop_in.stat().st_uid != self.root_uid or
                     self.drop_in.stat().st_gid != self.root_gid))
        if changed:
            self.backup(self.drop_in, "10-hardening.conf")
            self.drop_in.parent.mkdir(parents=True, exist_ok=True)
            self.drop_in.write_text(desired, encoding="utf-8")
            self.drop_in.chmod(0o644)
            if (self.drop_in.stat().st_uid, self.drop_in.stat().st_gid) != (self.root_uid, self.root_gid):
                os.chown(self.drop_in, self.root_uid, self.root_gid)
            self.log(f"WRITE {self.drop_in}")
            try:
                self.run(["sshd", "-t"])
            except HardeningError:
                if old is None:
                    self.drop_in.unlink()
                else:
                    self.drop_in.write_bytes(old)
                    self.drop_in.chmod(old_mode)
                    if (self.drop_in.stat().st_uid, self.drop_in.stat().st_gid) != old_owner:
                        os.chown(self.drop_in, *old_owner)
                self.log(f"RESTORE {self.drop_in} after failed sshd -t")
                raise
            reload_result = self.run(["systemctl", "reload", "ssh"], allow_failure=True)
            if reload_result.returncode:
                self.run(["systemctl", "restart", "ssh"])
        self.verify()
        self.key_instructions()
        self.say(f"Backup: {self.backup_dir}")
        self.rollback()

    def rollback(self):
        self.say("Rollback:")
        self.say("  sudo rm /etc/ssh/sshd_config.d/10-hardening.conf && sudo systemctl restart ssh")
        home = self.home or Path("~" + self.user)
        self.say(f"  sudo cp -a {self.backup_dir / 'authorized_keys'} {home / '.ssh' / 'authorized_keys'}  # if backed up")

    def dry_run(self, key_specs):
        self.say("Dry run: Phase 2 SSH changes that may be needed (state is not inspected).")
        self.say(f"Backup directory: {self.backup_dir} (mode 0700)")
        for source, label in key_specs:
            self.say(f"VALIDATE and ADD if absent: {source} (label {label})")
        self.say(f"WRITE if needed: {self.drop_in}\n{desired_config(self.user).rstrip()}")
        self.say("RUN if changed: sshd -t; systemctl reload ssh (restart on reload failure)")
        self.say("VERIFY: sshd -T; ss -ltn")
        self.key_instructions()
        self.rollback()

    def key_instructions(self):
        self.say("Phone (Termux): pkg install openssh; ssh-keygen -t ed25519 -C phone")
        self.say("Laptop/desktop: ssh-keygen -t ed25519 -C <device>")
        self.say("Copy each .pub file here, then rerun with --add-key PUBKEY_FILE --label NAME.")


def main(argv=None, *, runner=command_runner, euid=None, out=None, **paths):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply changes (requires root)")
    parser.add_argument("--user", default="quartermeat")
    parser.add_argument("--add-key", action="append", default=[], metavar="PUBKEY_FILE")
    parser.add_argument("--label", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)
    if len(args.add_key) != len(args.label):
        parser.error("each --add-key requires one --label")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", args.user):
        parser.error("invalid --user")
    if args.apply and (os.geteuid() if euid is None else euid) != 0:
        print("--apply requires root; run with sudo", file=sys.stderr)
        return 2
    hardener = Hardener(args.user, runner=runner, out=out, **paths)
    try:
        if args.apply:
            hardener.apply(list(zip(args.add_key, args.label)))
        else:
            hardener.dry_run(list(zip(args.add_key, args.label)))
    except (HardeningError, OSError, UnicodeError) as exc:
        print(f"Phase 2 failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
