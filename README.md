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
