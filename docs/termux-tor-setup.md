# Phone side: Termux SSH over the onion service

Run these in order. The PC steps need `sudo`. Run everything from `~/worktrees/hardening-phase1`.

## 1. PC: install the phone's SSH key

1. On the phone: Settings → System → Developer options → **USB debugging** on. Plug in and accept the "Allow USB debugging" prompt.
2. On the PC: `adb devices` should list the phone as `device`, not `unauthorized`.
3. On the PC: `python3 import_phone_key.py`. It validates the key, shows its fingerprint, and asks before running the phase 2 install with sudo.

## 2. PC: create the onion service and the phone's client key

```
sudo python3 phase3_onion.py --apply --add-client phone
```

The last lines print one secret line: `<56 chars>:descriptor:x25519:<key>`. It appears **once only**. The 56 characters before the first `:` are the address (add `.onion` when you use it).

## 3. Phone: Termux Tor client

```
pkg install tor openssh netcat-openbsd termux-api
mkdir -p ~/.tor/auth && chmod 700 ~/.tor ~/.tor/auth
nano ~/.tor/auth/home.auth_private      # paste the secret line from step 2, save
chmod 600 ~/.tor/auth/home.auth_private
cat > $PREFIX/etc/tor/torrc <<'EOF'
SocksPort 127.0.0.1:9050
ClientOnionAuthDir /data/data/com.termux/files/home/.tor/auth
EOF
```

Getting the secret line onto the phone: type it while docked (the terminal is already on the big screen), or copy it over `adb` and delete it right away:

```
# on the PC, paste the line into a file first, then:
adb push home.auth_private /sdcard/Download/ && shred -u home.auth_private
# in Termux:
mv ~/storage/downloads/home.auth_private ~/.tor/auth/ && chmod 600 ~/.tor/auth/home.auth_private
```

## 4. Phone: SSH config

```
cat >> ~/.ssh/config <<'EOF'
Host home
  HostName <56-char-address>.onion
  User quartermeat
  ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
EOF
```

## 5. Test

```
termux-wake-lock
tor &            # wait for "Bootstrapped 100%"
ssh home
```

For a real test, turn Wi‑Fi off and use mobile data. If it hangs, check that the address in `~/.ssh/config` matches the secret line and that `tor` printed no `ClientOnionAuthDir` errors.

## Keep secret

The `.onion` address, the `auth_private` line, and `~/.ssh/id_ed25519` all stay on the phone. Never paste them into chat, repos or notes.
