# Handoff

Updated 2026-11-01.

## State

| Piece | Version | On this host |
| --- | --- | --- |
| Phase 1: LAN-only UFW, security auto-updates | v0.1.0 | Applied |
| Phase 2: sshd on 127.0.0.1, key-only | v0.1.0 | Applied |
| Phase 2 idle timeouts (`ChannelTimeout session=10m`, `UnusedConnectionTimeout 1m`, ClientAlive 60×3) | v0.3.1 | **Not applied**. Needs `sudo python3 phase2_ssh.py --apply` |
| Phase 3: client-authorized Tor onion → localhost sshd | v0.2.0 | Applied. One client, `phone`. `ssh home` works from the Pixel Terminal app |
| Phone key import (`import_phone_key.py`) and secret push (`push_onion_auth.py`) | v0.2.2 | Used once and worked |
| `hardening-check` (Go, rootless) | v0.3.1 | Installed at `~/.local/bin/hardening-check` |

GitHub: https://github.com/quartermeat/debian-hardening (public). The remote has v0.2.2 and lags local `main`.

## Pending user decisions

1. Apply phase 2 again with sudo to get the idle timeouts. Until then `hardening-check` fails "SSH configuration".
2. Listener baseline: `hardening-check --write-baseline` allows `kdeconnectd` (1716), `owncast` (1935) and `spotify` (57621 and a random port). Decide first whether Owncast should listen on all interfaces.
3. Approve the nightly check: `agent-bridge approve schedule-41818b5d39577d4c664d1226`. It runs at 03:30 with `--notify`. The source entry is `~/.config/agent-bridge-schedules/hardening-check.yaml`.
4. Push local commits after v0.2.2 to GitHub, after a secret scan.

## Phone notes

- The Pixel's **Terminal** app is a Debian VM (user `droid`). `/mnt/shared` is `/storage/emulated/0`, and sudo cannot read it, so copy files to `/tmp` first.
- Docked on the Dell Thunderbolt dock through the KVM hub: the Logitech Bolt receiver's mouse is dropped by Android about 1.5 s after it connects. Use the LIFT mouse on Bluetooth (another Easy-Switch channel). Keys go to the last-focused display, so click the window on the monitor.
- Turn off Wireless debugging when not in use.

## Secrets

The onion address, `*.auth_private` lines and private keys never go in this repo, in chat, or in notes. The client auth line is printed once by `phase3_onion.py --add-client`.
