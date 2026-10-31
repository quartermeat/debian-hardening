# Phase 1 hardening implementation

Status: done. No files under `/etc` were changed for this follow-up. No commit was made.

## Delivered

- `phase1_firewall.py`: standard-library-only, rootless dry run by default; root-only apply; CIDR validation; package detection and installation; dated pre-change backups and action log; guarded, LAN-only UFW rules; IPv6, firewall defaults, and logging; security-only unattended-upgrades drop-in; timer enablement; final verification and rollback instructions.
- `test_phase1_firewall.py`: eleven rootless tests with an injected command runner and temporary files, covering dry run, root refusal, exact rules, idempotent settings, unexpected-rule stop, invalid CIDR, apply behavior, and missing or failing backup commands.
- `README.md`: usage, verification, and rollback.

## Follow-up fix

- Backup skips `iptables-save` or `nft` when its binary is absent and logs `SKIP <cmd>: not installed`.
- Backup preserves stdout and records stderr and exit status when a backup command fails, then continues.
- Other missing commands raise `HardeningError` with the command name instead of leaking `FileNotFoundError`.

## Empty UFW rule list fix

- `parse_added_rules` accepts the `(None)` line from `ufw show added` as an empty rule list and still rejects other unrecognized lines.
- Tests use the exact empty-output text and confirm a second apply with packages installed does not add duplicate rules or reinstall packages.

## Checks

- `python3 -m py_compile phase1_firewall.py` — pass.
- `python3 -m unittest -v test_phase1_firewall.py` — pass (11 tests).
- `python3 phase1_firewall.py` — pass; lists conditional commands, writes, and all seven LAN rules without root.
- `git diff --check` — pass.

Apply was not run against a live firewall. The dry run lists every command or write that may be needed; an exact per-host mutation list requires inspecting privileged system state during apply.

## Phase 2 SSH implementation

- Added `phase2_ssh.py`: rootless dry run, root-only apply, optional ed25519 public keys with labels, duplicate detection, user ownership and 0700/0600 key permissions, and a root-owned 0644 localhost-only SSH drop-in.
- Checks that the main SSH config includes drop-ins before any `Match`, tests the changed config with `sshd -t`, restores the previous drop-in on test failure, then reloads SSH (restarts if reload fails). A matching second run skips the reload.
- Verifies `sshd -T` values and rejects public port 22 listeners from `ss -ltn`. It warns when `authorized_keys` is empty, prints per-device key generation instructions and rollback commands, and logs actions under a dated mode 0700 backup directory.
- Added `test_phase2_ssh.py` with temporary paths and an injected command runner. No live SSH or `/etc` configuration was changed.

### Phase 2 checks

- `python3 -m py_compile phase2_ssh.py` — pass.
- `python3 -m unittest -v test_phase1_firewall.py test_phase2_ssh.py` — pass (20 tests).
- `python3 phase2_ssh.py` — pass; rootless dry run.
- `git diff --check` — pass.

## Phase 3 implementation

- Added `phase3_onion.py`: rootless dry run, root-only apply, Tor config include and SSH onion drop-in, Tor-owned service and client directories, x25519 client authorization generated through OpenSSL, dated backups and action log, idempotent reload, rollback on failure, and post-apply verification.
- Client private key material remains in memory and is printed once after successful verification. The onion hostname appears only with `--show-address` or after successful apply, never in the action log.
- Added `test_phase3_onion.py` with injected command output and temporary paths for dry run, root gate, known base32 vector, client management, idempotency, config failure restoration, hostname display, and new public listener detection.
- Added Phase 3 setup and rollback instructions to `README.md`. No live Tor or SSH configuration was changed.
