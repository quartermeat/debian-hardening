# Phase 3 plan: authorized onion service for SSH

Status: draft plan (EPM), 2026-10-31. Nothing here is implemented yet.

## Goal

Make SSH from the phone (Termux) work from anywhere, with no inbound ports open. Use a Tor v3 onion service with client authorization, forwarding to the existing localhost-only sshd.

## Current state (observed 2026-10-31)

- sshd listens on `127.0.0.1:22` only. Phase 2 drop-in `/etc/ssh/sshd_config.d/10-hardening.conf` turns off passwords, root login and X11, and sets `AllowUsers quartermeat`.
- `~/.ssh/authorized_keys` exists but is **empty**, so no device can log in yet.
- `tor` 0.4.9.15 and `torsocks` are installed. `tor@default` is active with SOCKS on `127.0.0.1:9050`. `/etc/tor/torrc` has only comments, and there is no `torrc.d`.
- UFW is active (phase 1, LAN-only rules). An onion service needs no new inbound rule.

## Design

1. **Onion service.** Add a `%include /etc/tor/torrc.d/*.conf` line to torrc (back it up first). Then create `/etc/tor/torrc.d/50-ssh-onion.conf`:
   ```
   HiddenServiceDir /var/lib/tor/ssh/
   HiddenServicePort 22 127.0.0.1:22
   ```
   v3 is the only version. Mode 0700, owned by `debian-tor`.
2. **Client authorization.** Give each device an x25519 keypair. Put the public half in `/var/lib/tor/ssh/authorized_clients/<label>.auth` (`descriptor:x25519:<pubkey>`). Without a key, the service descriptor stays unreadable, so the address alone is useless.
3. **Phone side (Termux).** `pkg install tor openssh`. Put the private key in `~/.tor/auth/<label>.auth_private`, with `ClientOnionAuthDir` set in Termux's torrc. `~/.ssh/config`:
   ```
   Host home
     HostName <addr>.onion
     User quartermeat
     ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
   ```
   Orbot is an alternative if Termux tor is unreliable in the background.
4. **SSH key.** Run `ssh-keygen -t ed25519 -C phone` in Termux, copy the `.pub` over, then `sudo python3 phase2_ssh.py --apply --add-key phone.pub --label phone`. Phase 2 already supports this.

## Deliverable (for a Codex coding worker)

- `phase3_onion.py`: standard library only, rootless dry run by default, root-only `--apply`. Same patterns as phases 1 and 2: dated backups under `/root/hardening-backups/YYYY-MM-DD/phase3/`, an action log, idempotent re-runs, `tor --verify-config` before reload, and restore on failure.
- Options: `--add-client LABEL` generates an x25519 pair. Write the `.auth` file and print the client `.auth_private` line once, never logging the private key. `--remove-client LABEL`. `--show-address` prints the hostname.
- Verify: tor active, hostname file present, `authorized_clients` non-empty (warn if empty), sshd still bound only to `127.0.0.1`, no new public listeners in `ss -ltn`.
- `test_phase3_onion.py`: injected command runner and temporary paths, as in the earlier tests.
- README section: usage, Termux setup, rollback (remove the drop-in and the include line, reload tor, optionally delete `/var/lib/tor/ssh/`).

### Key generation

x25519 needs either the `cryptography` package or `openssl genpkey -algorithm x25519`, with the raw 32 bytes encoded as base32 without padding. Prefer `openssl` (already present) so the script stays standard-library only. Tests must cover the encoding against a known vector.

## Acceptance

- Dry run lists every write and command with no root needed.
- After apply, from the phone on mobile data (Wi-Fi off): `ssh home` succeeds. A client without the auth key cannot reach the descriptor.
- Re-running apply changes nothing and skips the reload.
- `python3 -m unittest test_phase1_firewall.py test_phase2_ssh.py test_phase3_onion.py` passes.

## Risks and open questions

- **Lockout:** low, since local console access stays. Keep a local session open during the first test.
- **Phone battery/background:** Android may kill Termux tor. Use `termux-wake-lock` or Orbot. This is a user choice.
- **Address secrecy:** treat the `.onion` hostname and the client private keys as secrets. Keep them out of repos, chat and memory.
- **Open:** one client key per device (recommended) or a shared key? Add Mosh later (UDP doesn't go over Tor, so no)?

## Order of work

1. Commit phases 1 and 2 as v0.1.0. They're still uncommitted, and the `__pycache__` files should be dropped from the index and gitignored.
2. Run a Codex coding worker job for `phase3_onion.py`, plus tests and the README section.
3. Review, then the user runs `--apply` and tests from the phone.
