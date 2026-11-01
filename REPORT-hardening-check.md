# Rootless nightly hardening check

## Implemented

- Added `cmd/hardening-check` as a Go standard-library command and `go.mod` for Go 1.24.
- Checks four systemd units, UFW, SSH, Tor SSH-onion configuration and include, unattended-upgrades configuration, TCP listeners, and authorized SSH keys. Each check returns PASS or FAIL with a one-line detail; `--json` emits the version 1 result object.
- `--notify` names failed checks in a critical desktop notification and ignores notification errors.
- `--write-baseline` saves all current non-loopback TCP listeners to the user allowlist. Exposed port 22 always fails even if listed. Other allowed non-loopback listeners remain visible in the check detail.
- Uses an injected command runner and filesystem root in tests. The command does not read Tor private service files, onion hostname, or SSH key material beyond authorized public-key lines.

## Verification

- `gofmt -l cmd`: empty output.
- `GOCACHE=/tmp/hardening-check-gocache go vet ./...`: pass.
- `GOCACHE=/tmp/hardening-check-gocache go test ./...`: pass.
- `GOCACHE=/tmp/hardening-check-gocache go build -o /tmp/hardening-check ./cmd/hardening-check`: pass.
- `python3 -m unittest test_phase1_firewall.py test_phase2_ssh.py test_phase3_onion.py test_import_phone_key.py`: 40 tests pass.
- `git diff --check`: pass.

## Host run

`/tmp/hardening-check` exited 1. UFW, SSH, Tor drop-in, Tor include, unattended-upgrades configuration, and authorized keys passed. All four systemd checks failed because this sandbox cannot connect to the system bus (`Operation not permitted`). The listener check failed because `ss -ltnH` reported `Cannot open netlink socket: Operation not permitted` despite returning exit status 0; the parser reported `unexpected ss address: "socket:"`. A normal unsandboxed user session is needed to verify live service and socket state.

No files were committed or installed into a user bin directory or systemd.

## Review fixes

- Listener collection now uses `ss -ltnpH` and supports `process:NAME`, `addr:port`, `*:port`, and bare `port` allowlist entries. Baselines prefer a visible process name and retain the observed address as a comment; hidden processes use `addr:port`.
- Command failures, netlink error text, and malformed `ss` lines produce a failed TCP check with `cannot read sockets` detail. Baseline writes reject the same failures.
- Regression tests cover changing process ports, hidden process fallback, port rules, and socket read errors.
- Verification: `gofmt -l cmd` had no output; `go vet ./...`, `go test ./...`, 40 Python unit tests, and `git diff --check` passed.
