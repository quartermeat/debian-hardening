import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

import phase3_onion as phase3


HOST = 'a' * 56 + '.onion'
PRIVATE = bytes(range(32))
PUBLIC = bytes(range(32, 64))


class FakeRunner:
    def __init__(self, service):
        self.service = service
        self.calls = []
        self.fail_verify = False
        self.public_listener = False
        self.sockets = ('State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
                        'LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n')

    def __call__(self, argv, *, input=None):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv == ('openssl', 'genpkey', '-algorithm', 'x25519', '-outform', 'DER'):
            return subprocess.CompletedProcess(argv, 0, phase3.PRIVATE_DER_PREFIX + PRIVATE, b'')
        if argv == ('openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'):
            assert input == phase3.PRIVATE_DER_PREFIX + PRIVATE
            return subprocess.CompletedProcess(argv, 0, phase3.PUBLIC_DER_PREFIX + PUBLIC, b'')
        if argv[0] == 'tor' and argv[-1] == '--verify-config' and self.fail_verify:
            return subprocess.CompletedProcess(argv, 1, b'', b'bad tor config')
        if argv == ('systemctl', 'reload', 'tor@default'):
            (self.service / 'hostname').write_text(HOST + '\n')
        outputs = {
            ('ss', '-ltn'): self.sockets + ('LISTEN 0 128 0.0.0.0:1234 0.0.0.0:*\n' if self.public_listener else ''),
            ('sshd', '-T'): 'listenaddress 127.0.0.1:22\n',
            ('systemctl', 'is-active', 'tor@default'): 'active\n',
        }
        return subprocess.CompletedProcess(argv, 0, outputs.get(argv, ''), '')


class PhaseThreeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.torrc = root / 'torrc'
        self.torrc.write_text('# stock config\n')
        self.drop = root / 'torrc.d' / '50-ssh-onion.conf'
        self.service = root / 'ssh'
        self.service.mkdir()
        self.backup = root / 'backup'
        self.runner = FakeRunner(self.service)
        self.out = io.StringIO()
        self.paths = dict(torrc=self.torrc, drop_in=self.drop,
                          service_dir=self.service, backup_dir=self.backup,
                          tor_uid=phase3.os.getuid(), tor_gid=phase3.os.getgid())

    def main(self, args, euid=0):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = phase3.main(args, runner=self.runner, out=self.out, euid=euid, **self.paths)
        return code, err.getvalue()

    def test_known_vector(self):
        self.assertEqual(phase3.b32(bytes(range(32))),
                         'AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ')
        self.assertEqual(phase3.raw_der(phase3.PRIVATE_DER_PREFIX + PRIVATE,
                                        phase3.PRIVATE_DER_PREFIX), PRIVATE)

    def test_dry_run_rootless_no_writes(self):
        self.assertEqual(self.main(['--add-client', 'phone'], euid=1000)[0], 0)
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.runner.calls, [])
        self.assertIn('openssl genpkey', self.out.getvalue())

    def test_apply_requires_root(self):
        code, error = self.main(['--apply'], euid=1000)
        self.assertEqual(code, 2)
        self.assertIn('requires root', error)
        self.assertEqual(self.runner.calls, [])

    def test_apply_idempotent(self):
        self.assertEqual(self.main(['--apply'])[0], 0)
        self.assertEqual(self.main(['--apply'])[0], 0)
        self.assertEqual(self.runner.calls.count(('systemctl', 'reload', 'tor@default')), 1)
        self.assertEqual(self.runner.calls.count(self.verify_command()), 1)
        self.assertEqual(self.torrc.read_text().count(phase3.INCLUDE), 1)
        self.assertEqual(self.drop.read_text(), phase3.CONFIG)
        self.assertIn('Warning: no authorized onion clients; the service publishes an unauthenticated descriptor.', self.out.getvalue())

    def test_client_secret_printed_once_and_not_stored(self):
        self.assertEqual(self.main(['--apply', '--add-client', 'phone'])[0], 0)
        secret = phase3.b32(PRIVATE)
        auth = self.service / 'authorized_clients' / 'phone.auth'
        self.assertEqual(auth.read_text(), f'descriptor:x25519:{phase3.b32(PUBLIC)}\n')
        self.assertEqual(auth.stat().st_mode & 0o777, 0o600)
        client_line = f'{HOST.removesuffix(".onion")}:descriptor:x25519:{secret}'
        self.assertEqual(self.out.getvalue().splitlines().count(client_line), 1)
        self.assertNotIn(f'{HOST}:descriptor:x25519:', self.out.getvalue())
        self.assertNotIn(secret, (self.backup / 'actions.log').read_text())
        self.assertNotIn(secret, auth.read_text())
        self.assertNotIn(HOST, (self.backup / 'actions.log').read_text())
        self.assertEqual(self.main(['--apply', '--add-client', 'phone'])[0], 1)
        self.assertEqual(self.runner.calls.count(('systemctl', 'reload', 'tor@default')), 1)

    def test_remove_client(self):
        self.assertEqual(self.main(['--apply', '--add-client', 'phone'])[0], 0)
        calls_before = list(self.runner.calls)
        code, error = self.main(['--apply', '--remove-client', 'phone'])
        self.assertEqual(code, 1)
        self.assertIn('last client', error)
        self.assertEqual(self.runner.calls[len(calls_before):], [('ss', '-ltn')])
        self.assertTrue((self.service / 'authorized_clients' / 'phone.auth').exists())
        self.assertEqual(self.main(['--apply', '--add-client', 'laptop'])[0], 0)
        self.assertEqual(self.main(['--apply', '--remove-client', 'phone'])[0], 0)
        self.assertFalse((self.service / 'authorized_clients' / 'phone.auth').exists())
        self.assertTrue((self.service / 'authorized_clients' / 'laptop.auth').exists())
        self.assertEqual(self.runner.calls.count(('systemctl', 'reload', 'tor@default')), 3)
        self.assertEqual(self.main(['--apply', '--remove-client', 'laptop', '--allow-no-clients'])[0], 0)
        self.assertFalse((self.service / 'authorized_clients' / 'laptop.auth').exists())
        self.assertIn('unauthenticated descriptor', self.out.getvalue())

    def verify_command(self):
        return ('tor', '--defaults-torrc', phase3.TOR_SERVICE_DEFAULTS,
                '-f', str(self.torrc), '--RunAsDaemon', '0', '--verify-config')

    def test_verify_uses_service_defaults_on_apply_and_rollback(self):
        fake = self.runner
        original = fake.__call__
        def fail_after_reload(argv, *, input=None):
            if tuple(argv) == ('sshd', '-T'):
                return subprocess.CompletedProcess(argv, 0, 'listenaddress 0.0.0.0:22\n', '')
            return original(argv, input=input)
        self.runner = fail_after_reload
        code, error = self.main(['--apply'])
        self.assertEqual(code, 1)
        self.assertIn('sshd is not bound', error)
        self.assertEqual(fake.calls.count(self.verify_command()), 2)

    def test_hostname_waits_for_tor_to_write_it(self):
        class Clock:
            now = 0
            def __call__(self):
                return self.now
            def sleep(self, seconds):
                self.now += seconds
                if self.now >= 2:
                    (self_service / 'hostname').write_text(HOST + '\n')
        self_service = self.service
        clock = Clock()
        self.paths.update(clock=clock, sleep=clock.sleep)
        original = self.runner.__call__
        def delayed(argv, *, input=None):
            result = original(argv, input=input)
            if tuple(argv) == ('systemctl', 'reload', 'tor@default'):
                (self.service / 'hostname').unlink(missing_ok=True)
            return result
        self.runner = delayed
        self.assertEqual(self.main(['--apply'])[0], 0)
        self.assertEqual(clock.now, 2)

    def test_hostname_wait_times_out_and_rolls_back(self):
        class Clock:
            now = 0
            def __call__(self):
                return self.now
            def sleep(self, seconds):
                self.now += seconds
        clock = Clock()
        self.paths.update(clock=clock, sleep=clock.sleep)
        original = self.runner.__call__
        def no_hostname(argv, *, input=None):
            result = original(argv, input=input)
            (self.service / 'hostname').unlink(missing_ok=True)
            return result
        self.runner = no_hostname
        code, error = self.main(['--apply'])
        self.assertEqual(code, 1)
        self.assertIn('hostname is missing', error)
        self.assertEqual(clock.now, 30)
        self.assertEqual(self.torrc.read_text(), '# stock config\n')

    def test_failed_config_restores_files(self):
        self.drop.parent.mkdir()
        self.drop.write_text('old config\n')
        self.runner.fail_verify = True
        code, error = self.main(['--apply'])
        self.assertEqual(code, 1)
        self.assertIn('bad tor config', error)
        self.assertEqual(self.torrc.read_text(), '# stock config\n')
        self.assertEqual(self.drop.read_text(), 'old config\n')
        self.assertEqual((self.backup / '50-ssh-onion.conf').read_text(), 'old config\n')
        self.assertNotIn(('systemctl', 'reload', 'tor@default'), self.runner.calls)

    def test_show_address(self):
        (self.service / 'hostname').write_text(HOST + '\n')
        self.assertEqual(self.main(['--show-address'], euid=1000)[0], 0)
        self.assertEqual(self.out.getvalue(), HOST + '\n')
        self.assertEqual(self.runner.calls, [])

    def test_existing_public_ssh_listener_rejected(self):
        self.runner.sockets += 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
        code, error = self.main(['--apply'])
        self.assertEqual(code, 1)
        self.assertIn('Public SSH listener', error)
        self.assertEqual(self.torrc.read_text(), '# stock config\n')

    def test_new_public_listener_rejected(self):
        self.runner.public_listener = True
        # The new socket appears only after reload.
        original = self.runner.__call__
        def changing(argv, *, input=None):
            if tuple(argv) == ('ss', '-ltn') and ('systemctl', 'reload', 'tor@default') not in self.runner.calls:
                old = self.runner.public_listener
                self.runner.public_listener = False
                result = original(argv, input=input)
                self.runner.public_listener = old
                return result
            return original(argv, input=input)
        class Wrapper:
            def __call__(self, argv, *, input=None):
                return changing(argv, input=input)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(phase3.main(['--apply'], runner=Wrapper(), out=self.out, euid=0, **self.paths), 1)
        self.assertEqual(self.torrc.read_text(), '# stock config\n')


if __name__ == '__main__':
    unittest.main()
