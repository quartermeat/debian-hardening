# Phone side: Android Terminal (Debian VM) SSH over the onion service

The Pixel "Terminal" app runs Debian as user `droid`. In it, `/mnt/shared` is the phone's storage root (`/storage/emulated/0`).

## 1. PC: move the secret line to the phone

On the PC (Konsole):

```
nano ~/home.auth_private          # paste the full secret line from phase3_onion.py, save
adb push ~/home.auth_private /storage/emulated/0/ && shred -u ~/home.auth_private
```

## 2. Phone (Terminal): Tor client

```
sudo apt update && sudo apt install -y tor netcat-openbsd openssh-client
sudo install -d -m 700 -o debian-tor -g debian-tor /var/lib/tor/onion_auth
sudo mv /mnt/shared/home.auth_private /var/lib/tor/onion_auth/
sudo chown debian-tor:debian-tor /var/lib/tor/onion_auth/home.auth_private
sudo chmod 600 /var/lib/tor/onion_auth/home.auth_private
echo 'ClientOnionAuthDir /var/lib/tor/onion_auth' | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor || sudo service tor restart
```

## 3. Phone: SSH config

The address is the 56 characters before the first `:` in the secret line:

```
ADDR=$(sudo cut -d: -f1 /var/lib/tor/onion_auth/home.auth_private)
cat >> ~/.ssh/config <<EOF
Host home
  HostName $ADDR.onion
  User quartermeat
  ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
EOF
chmod 600 ~/.ssh/config
```

## 4. Test

`ssh home`. The first connection can take 10–30 s. For a real test, turn Wi‑Fi off.

If it fails: run `sudo journalctl -u tor@default -n 30` (or `-u tor`) and look for auth or bootstrap errors.

## Keep secret

Keep the address and the `auth_private` line on the phone only. Never put them in chat, repos or notes.
