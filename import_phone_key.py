#!/usr/bin/env python3
"""Import a phone's Ed25519 SSH public key over adb and run phase2_ssh.py.

The default source is /storage/emulated/0/phone.pub. Use --file for a key
transferred by hand. The key is held in a private temporary directory while
phase 2 runs, then removed. --dry-run validates and prints the install command.
"""

import argparse
import base64
import binascii
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


DEFAULT_REMOTE = "/storage/emulated/0/phone.pub"
KEY_LINE = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([^\r\n]+))?\Z")


class ImportErrorMessage(Exception):
    pass


def command_runner(argv):
    """Single gateway for external commands; tests can inject a fake."""
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def run_command(runner, argv):
    try:
        result = runner(list(argv))
    except FileNotFoundError as exc:
        raise ImportErrorMessage(f"Command not installed: {argv[0]}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ImportErrorMessage(
            f"Command failed ({result.returncode}): {shlex.join(argv)}"
            + (f"\n{detail}" if detail else ""))
    return result


def check_device(runner):
    result = run_command(runner, ["adb", "devices"])
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    ready = [serial for serial, state in devices if state == "device"]
    if len(ready) == 1 and len(devices) == 1:
        return
    if any(state == "unauthorized" for _, state in devices):
        raise ImportErrorMessage(
            "Phone is unauthorized. Unlock it and accept the USB debugging prompt; "
            "then retry. Enable USB debugging in Developer options if needed.")
    if not devices:
        raise ImportErrorMessage(
            "No adb device found. Connect the phone by USB, enable USB debugging "
            "in Developer options, and accept the prompt on the phone.")
    if len(devices) > 1:
        raise ImportErrorMessage("Multiple adb devices found. Disconnect all but the phone and retry.")
    raise ImportErrorMessage(
        f"Phone is {devices[0][1]}. Unlock it, reconnect USB, enable USB debugging, "
        "and accept the prompt on the phone.")


def validate_key(data):
    if b"PRIVATE KEY" in data.upper():
        raise ImportErrorMessage("Private key material refused; use phone.pub only.")
    try:
        content = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ImportErrorMessage("Public key must be ASCII text.") from exc
    lines = content.splitlines()
    if len(lines) != 1:
        raise ImportErrorMessage("Expected exactly one ssh-ed25519 public key line.")
    match = KEY_LINE.fullmatch(lines[0])
    if not match:
        raise ImportErrorMessage("Expected one ssh-ed25519 <base64> public key with optional comment.")
    try:
        blob = base64.b64decode(match.group(1), validate=True)
    except binascii.Error as exc:
        raise ImportErrorMessage("Invalid public key base64.") from exc
    key_type = b"ssh-ed25519"
    if (len(blob) != 4 + len(key_type) + 4 + 32
            or blob[:4] != len(key_type).to_bytes(4, "big")
            or blob[4:4 + len(key_type)] != key_type
            or blob[4 + len(key_type):8 + len(key_type)] != (32).to_bytes(4, "big")):
        raise ImportErrorMessage("Invalid Ed25519 public key wire format (expected a 32-byte key).")
    return lines[0] + "\n"


def main(argv=None, *, runner=command_runner, input_fn=input, out=None, err=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", default=DEFAULT_REMOTE, metavar="PATH",
                        help=f"phone path to pull with adb (default: {DEFAULT_REMOTE})")
    parser.add_argument("--file", type=Path, metavar="PATH",
                        help="use a local public key file instead of adb")
    parser.add_argument("--label", default="phone", metavar="NAME",
                        help="authorized_keys label (default: phone)")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate and print the phase 2 command without running it")
    parser.add_argument("--yes", action="store_true", help="skip the y/N install confirmation")
    parser.add_argument("--delete-remote", action="store_true",
                        help="remove the phone's remote .pub file after successful install")
    args = parser.parse_args(argv)
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    if not args.label or args.label.strip() != args.label or any(c in args.label for c in "\r\n\t"):
        parser.error("label must be nonempty, single-line text")
    if args.file and args.delete_remote:
        parser.error("--delete-remote requires an adb source, not --file")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.remote):
        parser.error("--remote must be an absolute phone path using letters, digits, _, ., /, or -")

    try:
        with tempfile.TemporaryDirectory(prefix="phone-key-") as temp_dir:
            key_path = Path(temp_dir) / "phone.pub"
            if args.file is None:
                check_device(runner)
                run_command(runner, ["adb", "pull", args.remote, str(key_path)])
                data = key_path.read_bytes()
            else:
                data = args.file.read_bytes()
            key = validate_key(data)
            # Replace the pulled content with only the validated line, using 0600.
            key_path.write_text(key, encoding="ascii")
            key_path.chmod(0o600)
            fingerprint = run_command(runner, ["ssh-keygen", "-lf", str(key_path)])
            print(fingerprint.stdout.strip(), file=out)
            command = ["sudo", "python3", str(Path(__file__).resolve().parent / "phase2_ssh.py"),
                       "--apply", "--add-key", str(key_path), "--label", args.label]
            print(shlex.join(command), file=out)
            if args.dry_run:
                if args.delete_remote:
                    print("After install: " + shlex.join(["adb", "shell", "rm", "--", args.remote]), file=out)
                return 0
            try:
                confirmed = args.yes or input_fn("Install this key with phase 2? [y/N] ").strip().lower() == "y"
            except EOFError:
                confirmed = False
            if not confirmed:
                print("Cancelled.", file=out)
                return 0
            result = run_command(runner, command)
            if result.stdout:
                print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", file=out)
            if args.delete_remote:
                run_command(runner, ["adb", "shell", "rm", "--", args.remote])
                print(f"Removed remote public key: {args.remote}", file=out)
    except (ImportErrorMessage, OSError) as exc:
        print(f"Phone key import failed: {exc}", file=err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
