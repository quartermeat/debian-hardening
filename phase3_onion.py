#!/usr/bin/env python3
"""Phase 3: Tor v3 client-authorized onion service for localhost SSH."""

import argparse
import base64
import datetime
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

TORRC = Path('/etc/tor/torrc')
DROP_IN = Path('/etc/tor/torrc.d/50-ssh-onion.conf')
SERVICE_DIR = Path('/var/lib/tor/ssh')
BACKUP_ROOT = Path('/root/hardening-backups')
INCLUDE = '%include /etc/tor/torrc.d/*.conf'
CONFIG = 'HiddenServiceDir /var/lib/tor/ssh/\nHiddenServicePort 22 127.0.0.1:22\n'
PRIVATE_DER_PREFIX = bytes.fromhex('302e020100300506032b656e04220420')
PUBLIC_DER_PREFIX = bytes.fromhex('302a300506032b656e032100')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]*\Z')
HOSTNAME = re.compile(r'[a-z2-7]{56}\.onion\Z')
TOR_SERVICE_DEFAULTS = '/usr/share/tor/tor-service-defaults-torrc'


class HardeningError(Exception):
    pass


def command_runner(argv, *, input=None):
    return subprocess.run(argv, input=input, capture_output=True, check=False)


def b32(raw):
    if len(raw) != 32:
        raise HardeningError('Expected 32-byte x25519 key')
    return base64.b32encode(raw).decode('ascii').rstrip('=')


def raw_der(data, prefix):
    if not data.startswith(prefix) or len(data) != len(prefix) + 32:
        raise HardeningError('Unexpected OpenSSL x25519 DER format')
    return data[len(prefix):]


def active_lines(content):
    return [line.strip() for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def socket_set(content):
    sockets = set()
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] != 'LISTEN':
            continue
        local = fields[3].lower()
        if local.startswith(('127.', '[::1]:', '::1:')):
            continue
        sockets.add(local)
    return sockets


class Hardener:
    def __init__(self, *, runner=command_runner, out=None, backup_dir=None,
                 torrc=TORRC, drop_in=DROP_IN, service_dir=SERVICE_DIR,
                 tor_uid=None, tor_gid=None, clock=time.monotonic, sleep=time.sleep):
        self.runner = runner
        self.out = out if out is not None else sys.stdout
        self.backup_dir = Path(backup_dir) if backup_dir is not None else BACKUP_ROOT / datetime.date.today().isoformat() / 'phase3'
        self.torrc = Path(torrc)
        self.drop_in = Path(drop_in)
        self.service_dir = Path(service_dir)
        self.tor_uid = tor_uid
        self.tor_gid = tor_gid
        self.clock = clock
        self.sleep = sleep
        self.log_path = self.backup_dir / 'actions.log'

    def say(self, message):
        print(message, file=self.out)

    def log(self, message):
        self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.backup_dir.chmod(0o700)
        with self.log_path.open('a', encoding='utf-8') as stream:
            stream.write(message + '\n')

    def run(self, argv, *, input=None):
        self.log('RUN ' + shlex.join(argv))
        try:
            result = self.runner(list(argv), input=input) if input is not None else self.runner(list(argv))
        except FileNotFoundError as exc:
            raise HardeningError(f'Command not installed: {argv[0]}') from exc
        if result.returncode:
            error = result.stderr.decode('utf-8', 'replace') if isinstance(result.stderr, bytes) else result.stderr
            raise HardeningError(f'Command failed ({result.returncode}): {shlex.join(argv)}: {error.strip()}')
        return result

    def output(self, argv):
        value = self.run(argv).stdout
        return value.decode('utf-8') if isinstance(value, bytes) else value

    def tor_identity(self):
        if self.tor_uid is None or self.tor_gid is None:
            import pwd
            try:
                account = pwd.getpwnam('debian-tor')
            except KeyError as exc:
                raise HardeningError('debian-tor account is missing') from exc
            self.tor_uid, self.tor_gid = account.pw_uid, account.pw_gid

    def check_path(self, path):
        if path.is_symlink():
            raise HardeningError(f'Refusing symlink: {path}')

    def snapshot(self, path):
        self.check_path(path)
        if not path.exists():
            return None
        stat = path.stat()
        return (path.read_bytes(), stat.st_mode & 0o777, stat.st_uid, stat.st_gid)

    def backup(self, path, snapshot):
        if snapshot is None:
            return
        dest = self.backup_dir / path.name
        if not dest.exists():
            self.log(f'BACKUP {path} -> {dest}')
            shutil.copy2(path, dest)

    def restore(self, path, snapshot):
        if snapshot is None:
            path.unlink(missing_ok=True)
        else:
            data, mode, uid, gid = snapshot
            path.write_bytes(data)
            path.chmod(mode)
            if (path.stat().st_uid, path.stat().st_gid) != (uid, gid):
                os.chown(path, uid, gid)
        self.log(f'RESTORE {path}')

    def write(self, path, data, mode, owner=None):
        self.check_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        if owner and (path.stat().st_uid, path.stat().st_gid) != owner:
            os.chown(path, *owner)
        self.log(f'WRITE {path}')

    def keys(self):
        private_der = self.run(['openssl', 'genpkey', '-algorithm', 'x25519', '-outform', 'DER']).stdout
        if isinstance(private_der, str):
            raise HardeningError('OpenSSL runner must return binary DER')
        private = raw_der(private_der, PRIVATE_DER_PREFIX)
        public_der = self.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], input=private_der).stdout
        public = raw_der(public_der, PUBLIC_DER_PREFIX)
        return b32(public), b32(private)

    def address(self):
        path = self.service_dir / 'hostname'
        self.check_path(path)
        if not path.exists():
            raise HardeningError(f'Onion hostname is missing: {path}')
        hostname = path.read_text(encoding='ascii').strip()
        if not HOSTNAME.fullmatch(hostname):
            raise HardeningError('Invalid onion hostname')
        return hostname

    def wait_for_address(self, timeout=30):
        deadline = self.clock() + timeout
        while True:
            try:
                return self.address()
            except HardeningError:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    raise
                self.sleep(min(1, remaining))

    def tor_verify_command(self):
        return ['tor', '--defaults-torrc', TOR_SERVICE_DEFAULTS,
                '-f', str(self.torrc), '--RunAsDaemon', '0', '--verify-config']

    def verify(self, baseline):
        if self.output(['systemctl', 'is-active', 'tor@default']).strip() != 'active':
            raise HardeningError('tor@default is not active')
        hostname = self.wait_for_address()
        clients = self.service_dir / 'authorized_clients'
        if not clients.is_dir() or not any(clients.glob('*.auth')):
            self.say('Warning: no authorized onion clients; the service publishes an unauthenticated descriptor.')
        effective = self.output(['sshd', '-T'])
        listeners = [line.split(maxsplit=1)[1].lower() for line in effective.splitlines()
                     if line.lower().startswith('listenaddress ')]
        if listeners != ['127.0.0.1:22']:
            raise HardeningError(f'sshd is not bound only to 127.0.0.1:22: {listeners}')
        sockets = self.output(['ss', '-ltn'])
        for local in socket_set(sockets):
            if local.endswith(':22'):
                raise HardeningError(f'Public SSH listener remains: {local}')
        if not any(line.split()[3] == '127.0.0.1:22' for line in sockets.splitlines()
                   if len(line.split()) >= 5 and line.startswith('LISTEN')):
            raise HardeningError('localhost SSH listener is missing')
        new_public = socket_set(sockets) - baseline
        if new_public:
            raise HardeningError(f'New non-loopback listener: {sorted(new_public)}')
        self.say('Verification passed: Tor active, onion hostname present, SSH local, no new public listeners.')
        return hostname

    def apply(self, add=None, remove=None, allow_no_clients=False):
        self.tor_identity()
        if add and remove:
            raise HardeningError('Choose either --add-client or --remove-client')
        baseline = socket_set(self.output(['ss', '-ltn']))
        old_torrc = self.snapshot(self.torrc)
        if old_torrc is None:
            raise HardeningError(f'Missing torrc: {self.torrc}')
        old_drop = self.snapshot(self.drop_in)
        clients = self.service_dir / 'authorized_clients'
        self.check_path(self.service_dir)
        self.check_path(clients)
        target = clients / f'{add or remove}.auth' if (add or remove) else None
        old_auth = self.snapshot(target) if target else None
        if add and old_auth is not None:
            raise HardeningError(f'Client label already exists: {add}')
        if remove and old_auth is None:
            raise HardeningError(f'Client label does not exist: {remove}')
        if remove and not allow_no_clients and not any(
                path != target for path in clients.glob('*.auth')):
            raise HardeningError('Refusing to remove the last client; use --allow-no-clients to make the service unauthenticated')
        torrc = old_torrc[0].decode('utf-8')
        include_needed = INCLUDE not in active_lines(torrc)
        drop_needed = old_drop is None or old_drop[0] != CONFIG.encode('utf-8')
        changed = include_needed or drop_needed or bool(add or remove)
        private = None
        if add:
            public, private = self.keys()
        created_service = not self.service_dir.exists()
        created_clients = not clients.exists()
        reload_attempted = False
        try:
            if changed:
                self.backup(self.torrc, old_torrc)
                self.backup(self.drop_in, old_drop)
                if target:
                    self.backup(target, old_auth)
                if include_needed:
                    self.write(self.torrc, (torrc.rstrip('\n') + '\n' + INCLUDE + '\n').encode(), old_torrc[1], (old_torrc[2], old_torrc[3]))
                if drop_needed:
                    self.write(self.drop_in, CONFIG.encode(), 0o644, (0, 0) if os.geteuid() == 0 else None)
                if not self.service_dir.exists():
                    self.service_dir.mkdir(mode=0o700, parents=True)
                    self.log(f'MKDIR {self.service_dir}')
                self.service_dir.chmod(0o700)
                if (self.service_dir.stat().st_uid, self.service_dir.stat().st_gid) != (self.tor_uid, self.tor_gid):
                    os.chown(self.service_dir, self.tor_uid, self.tor_gid)
                if not clients.exists():
                    clients.mkdir(mode=0o700)
                    self.log(f'MKDIR {clients}')
                clients.chmod(0o700)
                if (clients.stat().st_uid, clients.stat().st_gid) != (self.tor_uid, self.tor_gid):
                    os.chown(clients, self.tor_uid, self.tor_gid)
                if add:
                    self.write(target, f'descriptor:x25519:{public}\n'.encode(), 0o600, (self.tor_uid, self.tor_gid))
                elif remove:
                    target.unlink()
                    self.log(f'REMOVE {target}')
                self.run(self.tor_verify_command())
                reload_attempted = True
                self.run(['systemctl', 'reload', 'tor@default'])
            hostname = self.verify(baseline)
        except (HardeningError, OSError, UnicodeError):
            if changed:
                if include_needed:
                    self.restore(self.torrc, old_torrc)
                if drop_needed:
                    self.restore(self.drop_in, old_drop)
                if target:
                    self.restore(target, old_auth)
                if created_clients and clients.exists() and not any(clients.iterdir()):
                    clients.rmdir()
                if created_service and self.service_dir.exists() and not any(self.service_dir.iterdir()):
                    self.service_dir.rmdir()
                # Preserve the original failure. A failed verification did not
                # reload Tor; a later failure may have left it running with the
                # new configuration and needs the restored one reloaded.
                if reload_attempted:
                    try:
                        self.run(self.tor_verify_command())
                        self.run(['systemctl', 'reload', 'tor@default'])
                    except (HardeningError, OSError) as rollback_error:
                        self.log(f'ROLLBACK RELOAD FAILED: {rollback_error}')
            raise
        if add:
            self.say(f'{hostname.removesuffix(".onion")}:descriptor:x25519:{private}')
        else:
            self.say(f'Onion address: {hostname}')
        self.say(f'Backup: {self.backup_dir}')
        self.rollback()

    def rollback(self):
        self.say('Rollback: remove /etc/tor/torrc.d/50-ssh-onion.conf and the %include line from /etc/tor/torrc;')
        self.say('then run sudo ' + shlex.join(self.tor_verify_command()) + ' && sudo systemctl reload tor@default.')
        self.say('Optionally remove /var/lib/tor/ssh/ after saving any client authorization you still need.')

    def dry_run(self, add=None, remove=None, allow_no_clients=False):
        self.say('Dry run: Phase 3 actions that may be needed (no state inspected).')
        self.say(f'BACKUP if changed: {self.torrc}, {self.drop_in}, client auth -> {self.backup_dir}')
        self.say(f'WRITE if absent: {INCLUDE} in {self.torrc}')
        self.say(f'WRITE if changed: {self.drop_in}: {CONFIG.strip()}')
        self.say(f'MKDIR if absent: {self.service_dir}, {self.service_dir / "authorized_clients"} (Tor-owned, mode 0700)')
        if add:
            self.say(f'RUN: openssl genpkey -algorithm x25519 -outform DER; openssl pkey -inform DER -pubout -outform DER')
            self.say(f'WRITE if new: {self.service_dir / "authorized_clients" / (add + ".auth")} (mode 0600)')
        if remove:
            self.say(f'REMOVE if present: {self.service_dir / "authorized_clients" / (remove + ".auth")}')
            if not allow_no_clients:
                self.say('REFUSE if this is the last client; --allow-no-clients permits an unauthenticated service.')
        self.say('RUN if changed: ' + shlex.join(self.tor_verify_command()) + '; systemctl reload tor@default')
        self.say('VERIFY: systemctl is-active tor@default; hostname; authorized_clients; sshd -T; ss -ltn (before and after)')
        self.rollback()


def main(argv=None, *, runner=command_runner, euid=None, out=None, **paths):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='apply changes (requires root)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--add-client', metavar='LABEL')
    group.add_argument('--remove-client', metavar='LABEL')
    group.add_argument('--show-address', action='store_true')
    parser.add_argument('--allow-no-clients', action='store_true',
                        help='permit removing the last client, making the onion service unauthenticated')
    args = parser.parse_args(argv)
    if args.allow_no_clients and not args.remove_client:
        parser.error('--allow-no-clients requires --remove-client')
    for label in (args.add_client, args.remove_client):
        if label and not LABEL.fullmatch(label):
            parser.error('client label must contain only letters, digits, underscore, or hyphen and start with a letter or digit')
    if args.apply and (os.geteuid() if euid is None else euid) != 0:
        print('--apply requires root; run with sudo', file=sys.stderr)
        return 2
    hardener = Hardener(runner=runner, out=out, **paths)
    try:
        if args.show_address:
            hardener.say(hardener.address())
        elif args.apply:
            hardener.apply(args.add_client, args.remove_client, args.allow_no_clients)
        else:
            hardener.dry_run(args.add_client, args.remove_client, args.allow_no_clients)
    except (HardeningError, OSError, UnicodeError) as exc:
        print(f'Phase 3 failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
