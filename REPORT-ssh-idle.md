# SSH idle timeout change

Added `ChannelTimeout session=10m`, `UnusedConnectionTimeout 1m`, `ClientAliveInterval 60`, and `ClientAliveCountMax 3` to the phase 2 SSH drop-in. Phase 2 now verifies their effective `sshd -T` values, accepting both seconds and minute notation for the duration settings. The nightly checker requires the active `ChannelTimeout session=10m` directive.

Tests cover the old drop-in backup and one-time reload, a second no-op apply, preservation of existing `authorized_keys` when no key is added, effective-setting mismatches, and missing or commented timeout directives in the checker.

## Checks

- `python3 -m py_compile phase2_ssh.py`: pass
- `python3 -m unittest test_phase1_firewall.py test_phase2_ssh.py test_phase3_onion.py test_import_phone_key.py`: pass, 43 tests
- `python3 phase2_ssh.py`: pass, rootless dry run
- `test -z "$(gofmt -l cmd)"`: pass
- `GOCACHE=/tmp/hardening-idle-go-cache go vet ./...`: pass
- `GOCACHE=/tmp/hardening-idle-go-cache go test ./...`: pass
- `git diff --check`: pass

The default Go build cache is read only in this sandbox; the Go checks passed with a temporary cache. No live `sshd` or root apply was run.
