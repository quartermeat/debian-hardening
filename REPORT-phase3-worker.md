# Phase 3 worker report

Status: done. No commit or live `--apply` was performed.

## Changed files

- `phase3_onion.py` (new): rootless dry run; root-only apply; Tor include and SSH onion drop-in; x25519 client authorization through OpenSSL; dated backups and action log; config verification, conditional reload, restoration on failure, and post-apply checks.
- `test_phase3_onion.py` (new): 10 tests using temporary paths and injected commands.
- `README.md`: Phase 3 usage, Termux setup, key handling, and rollback.
- `REPORT.md`: Phase 3 implementation summary.
- `REPORT-phase3-worker.md`: this handoff report.

## Checks

- `python3 -m py_compile phase3_onion.py` — pass.
- `python3 -m unittest -v test_phase1_firewall.py test_phase2_ssh.py test_phase3_onion.py` — pass, 30 tests.
- `python3 phase3_onion.py` — pass, rootless dry run.
- `git diff --check` — pass.
- Actual `openssl genpkey` and `openssl pkey` DER parsing — pass, 32-byte private and public keys extracted.

## Open items

- Live application and mobile-data SSH test are for the user after review. The phone needs both Tor client authorization and a separate SSH public key installed through Phase 2.
- `--show-address` requires sufficient permission to read Tor's mode 0700 service directory; use `sudo` on the target host.

## Review fixes

- Tor config verification now uses the service defaults and configured torrc path in both apply and rollback. The printed rollback command matches.
- Hostname verification waits up to 30 seconds for Tor to write a valid address, with an injectable clock and sleep for deterministic tests.
- Client `.auth_private` output omits `.onion` from the address field.
- Removing the last client is refused unless `--allow-no-clients` is passed. README explains the unauthenticated descriptor consequence.
- Regression tests cover each fix, including the hostname timeout and rollback path.
- `python3 -m py_compile phase3_onion.py` — pass; full requested unittest suite — pass, 33 tests; rootless dry run — pass; `git diff --check` — pass.
