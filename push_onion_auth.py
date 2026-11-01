#!/usr/bin/env python3
"""Push the phase 3 onion client secret and a setup script to the phone over adb.

Usage: python3 push_onion_auth.py   (prompts for the secret line, hidden)
Then in the phone's Terminal app:   bash /mnt/shared/onion-phone-setup.sh
"""
import getpass
import os
import re
import subprocess
import sys
import tempfile

LINE = re.compile(r'[a-z2-7]{56}:descriptor:x25519:[A-Z2-7]{52}\Z')
REMOTE = '/storage/emulated/0/'

PHONE_SETUP = r'''#!/bin/sh
set -e
SRC=/tmp/home.auth_private
cp /mnt/shared/home.auth_private "$SRC"  # sudo cannot read /mnt/shared
DIR=/var/lib/tor/onion_auth
[ -f "$SRC" ] || { echo "missing $SRC"; exit 1; }
sudo apt-get update
sudo apt-get install -y tor netcat-openbsd openssh-client
sudo install -d -m 700 -o debian-tor -g debian-tor "$DIR"
sudo install -m 600 -o debian-tor -g debian-tor "$SRC" "$DIR/home.auth_private"
rm -f "$SRC"
grep -q '^ClientOnionAuthDir' /etc/tor/torrc || echo "ClientOnionAuthDir $DIR" | sudo tee -a /etc/tor/torrc >/dev/null
sudo systemctl restart tor 2>/dev/null || sudo service tor restart
ADDR=$(sudo cut -d: -f1 "$DIR/home.auth_private")
mkdir -p ~/.ssh && chmod 700 ~/.ssh
if ! grep -q '^Host home$' ~/.ssh/config 2>/dev/null; then
  cat >> ~/.ssh/config <<EOF
Host home
  HostName $ADDR.onion
  User quartermeat
  ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
EOF
fi
chmod 600 ~/.ssh/config
echo "Done. Wait ~30s for Tor to bootstrap, then: ssh home"
'''


def push(local, name):
    subprocess.run(['adb', 'push', local, REMOTE + name], check=True,
                   stdout=subprocess.DEVNULL)


def main():
    secret = getpass.getpass('Paste the secret line (hidden): ').strip()
    if not LINE.fullmatch(secret):
        sys.exit('That does not look like <56-char address>:descriptor:x25519:<52-char key>.')
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        auth = os.path.join(tmp, 'home.auth_private')
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secret + '\n')
        setup = os.path.join(tmp, 'onion-phone-setup.sh')
        with open(setup, 'w') as stream:
            stream.write(PHONE_SETUP)
        push(auth, 'home.auth_private')
        push(setup, 'onion-phone-setup.sh')
    print('Delete the pushed copies afterwards: adb shell rm /storage/emulated/0/home.auth_private /storage/emulated/0/onion-phone-setup.sh')
    print('Pushed. In the phone Terminal run: bash /mnt/shared/onion-phone-setup.sh')


if __name__ == '__main__':
    main()
