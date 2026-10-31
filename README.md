# Debian 13 Phase 1 hardening

`phase1_firewall.py` configures UFW for the specified LAN and enables automatic Debian security updates. It backs up existing UFW and apt configuration plus firewall rules under `/root/hardening-backups/YYYY-MM-DD/phase1/`, logs actions there, and skips settings that already match. The default run is a rootless dry run.

```sh
python3 phase1_firewall.py
sudo python3 phase1_firewall.py --apply
```

Use `--lan CIDR` to change the LAN. If existing UFW rules are outside the requested set, the script stops and prints them. Review them before using `--replace-rules`, which resets UFW rules after a backup.

Verify with `sudo ufw status verbose` and `sudo unattended-upgrade --dry-run`. The script runs both checks after applying.

Rollback: `sudo ufw disable`, restore the relevant files from the printed backup directory (including `/etc/ufw/`, `/etc/default/ufw`, and the two apt files), then `sudo rm /etc/apt/apt.conf.d/52hardening-unattended`. The script prints the specific restore commands.

## Phase 2: localhost-only SSH

`phase2_ssh.py` limits SSH to `127.0.0.1`, disables password and keyboard-interactive login, and accepts only ed25519 public keys. Remote access requires a later localhost bridge, such as the planned authorized onion service. The default run is a rootless dry run.

```sh
python3 phase2_ssh.py
sudo python3 phase2_ssh.py --apply --add-key /path/to/phone.pub --label phone
```

Repeat `--add-key PUBKEY_FILE --label NAME` for each device; omit both to install the SSH settings with no authorized keys. Generate a key on a phone in Termux with `pkg install openssh; ssh-keygen -t ed25519 -C phone`, or on a laptop or desktop with `ssh-keygen -t ed25519 -C <device>`. Copy each `.pub` file to this machine before applying. Use `--user NAME` to select an account other than `quartermeat`.

The script backs up an existing drop-in and `authorized_keys` under `/root/hardening-backups/YYYY-MM-DD/phase2/`, tests the SSH configuration before reloading, and checks effective settings and listeners afterward. It prints rollback commands. If a drop-in existed before applying, restore its backup instead of deleting it during rollback. Keep a local session available while checking SSH access through the planned bridge.

## Phase 3: authorized onion SSH

`phase3_onion.py` creates a Tor v3 onion service that forwards port 22 to the existing `127.0.0.1:22` sshd. It adds a Tor config include and a drop-in, creates Tor-owned service and client authorization directories, verifies the Tor config before reload, and checks Tor, SSH, the hostname, and network listeners afterward. It opens no inbound firewall port. The default run is a rootless dry run.

```sh
python3 phase3_onion.py
sudo python3 phase3_onion.py --apply --add-client phone
sudo python3 phase3_onion.py --show-address
```

The add command prints a single `<56-character-address-without-.onion>:descriptor:x25519:<private-key>` line. Save that line directly on the phone in `~/.tor/auth/phone.auth_private` with mode `0600`. It is not written to the server's files or action log. Treat both the private key and onion address as secrets. Add one client per device with a distinct label. `sudo python3 phase3_onion.py --apply --remove-client phone` revokes that device. Removing the last client is refused because the service would become unauthenticated and publish a public descriptor. To permit that explicitly, add `--allow-no-clients`. A repeated plain `--apply` skips the Tor reload when the config already matches.

In Termux, install Tor and OpenSSH (`pkg install tor openssh`), set `ClientOnionAuthDir ~/.tor/auth` in Termux's Tor config, start Tor, then add this SSH config:

```sshconfig
Host home
  HostName <address>.onion
  User quartermeat
  ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
```

Termux must have an `nc` that supports SOCKS5 (`-X 5 -x`). Generate the separate SSH login key with `ssh-keygen -t ed25519 -C phone`, copy its `.pub` file to this machine, and run `sudo python3 phase2_ssh.py --apply --add-key phone.pub --label phone`. Then test `ssh home` from the phone on mobile data with Wi-Fi off. A phone without the onion authorization key should not be able to fetch the descriptor. Keep a local session available during the first test.

Backups and the action log are under `/root/hardening-backups/YYYY-MM-DD/phase3/`. To roll back, restore the backed-up torrc and drop-in if they existed; otherwise remove `/etc/tor/torrc.d/50-ssh-onion.conf` and the added `%include /etc/tor/torrc.d/*.conf` line. Run `sudo tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --RunAsDaemon 0 --verify-config` and `sudo systemctl reload tor@default`. Optionally remove `/var/lib/tor/ssh/` after saving any authorization files needed for recovery. Removing the service directory changes the onion address.
