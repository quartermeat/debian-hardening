package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safeSS = "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"

func fixture(t *testing.T, ss string) inspector {
	t.Helper()
	root := t.TempDir()
	write := func(path, value string, mode os.FileMode) {
		t.Helper()
		dest := filepath.Join(root, strings.TrimPrefix(path, "/"))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/ufw/ufw.conf", "# ENABLED=no\nENABLED=yes\n", 0644)
	write("/etc/ssh/sshd_config.d/10-hardening.conf", "ListenAddress 127.0.0.1\nPasswordAuthentication no\n", 0644)
	write("/etc/tor/torrc.d/50-ssh-onion.conf", "HiddenServicePort 22 127.0.0.1:22\n", 0644)
	write("/etc/tor/torrc", "%include /etc/tor/torrc.d/*.conf\n", 0644)
	write("/etc/apt/apt.conf.d/52hardening-unattended", "", 0644)
	write("/home/test/.ssh/authorized_keys", "# comment\nssh-ed25519 AAAA test\n", 0600)
	write("/home/test/.config/hardening-check/allowed-listeners", "# approved\n0.0.0.0:443\n", 0600)
	return inspector{root: root, home: "/home/test", run: func(name string, args ...string) (string, error) {
		if name == "ss" {
			return ss, nil
		}
		if name == "systemctl" {
			return "active", nil
		}
		return "", errors.New("unexpected command")
	}}
}

func find(t *testing.T, result Result, name string) Check {
	t.Helper()
	for _, c := range result.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing check %q", name)
	return Check{}
}

func TestHealthyAndBaseline(t *testing.T) {
	i := fixture(t, safeSS)
	r := i.inspect()
	if !r.OK || len(r.Checks) != 11 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if c := find(t, r, "TCP listeners"); c.Status != "PASS" || !strings.Contains(c.Detail, "0.0.0.0:443") {
		t.Fatalf("listener detail: %+v", c)
	}
	if err := i.writeBaseline(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(i.baselinePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "0.0.0.0:443\n" {
		t.Fatalf("baseline: %q", b)
	}
}

func TestListenerFailures(t *testing.T) {
	cases := []struct{ name, ss, want string }{
		{"missing local SSH", "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n", "absent"},
		{"exposed SSH", safeSS + "LISTEN 0 128 [::]:22 [::]:*\n", "exposed SSH"},
		{"unknown listener", safeSS + "LISTEN 0 128 10.0.0.2:8080 0.0.0.0:*\n", "not allowlisted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := fixture(t, tc.ss)
			c := find(t, i.inspect(), "TCP listeners")
			if c.Status != "FAIL" || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("got %+v", c)
			}
		})
	}
}

func TestProcessAllowlistAndBaseline(t *testing.T) {
	spotify := "LISTEN 0 128 0.0.0.0:45017 0.0.0.0:* users:((\"spotify\",pid=123,fd=42))\n"
	i := fixture(t, safeSS+spotify)
	if err := i.writeBaseline(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(i.baselinePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "0.0.0.0:443\nprocess:spotify # 0.0.0.0:45017\n" {
		t.Fatalf("baseline: %q", b)
	}
	i.run = func(name string, args ...string) (string, error) {
		if name == "ss" {
			if strings.Join(args, " ") != "-ltnpH" {
				t.Fatalf("ss args: %v", args)
			}
			return safeSS + strings.Replace(spotify, "45017", "45678", 1), nil
		}
		return "active", nil
	}
	if c := find(t, i.inspect(), "TCP listeners"); c.Status != "PASS" {
		t.Fatalf("dynamic port: %+v", c)
	}
	i.run = func(name string, args ...string) (string, error) {
		if name == "ss" {
			return safeSS + "LISTEN 0 128 0.0.0.0:45678 0.0.0.0:*\n", nil
		}
		return "active", nil
	}
	if c := find(t, i.inspect(), "TCP listeners"); c.Status != "FAIL" || !strings.Contains(c.Detail, "not allowlisted") {
		t.Fatalf("hidden process: %+v", c)
	}
	for _, rule := range []string{"*:45678", "45678", "0.0.0.0:45678"} {
		if err := os.WriteFile(i.baselinePath(), []byte("0.0.0.0:443\n"+rule+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if c := find(t, i.inspect(), "TCP listeners"); c.Status != "PASS" {
			t.Fatalf("rule %q: %+v", rule, c)
		}
	}
}

func TestSocketReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		err          error
	}{
		{"netlink text", "Cannot open netlink socket: Operation not permitted", nil},
		{"command error", "Cannot open netlink socket: Operation not permitted", errors.New("exit status 1")},
		{"malformed line", safeSS + "socket: broken\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := fixture(t, safeSS)
			i.run = func(name string, args ...string) (string, error) {
				if name == "ss" {
					return tc.output, tc.err
				}
				return "active", nil
			}
			c := find(t, i.inspect(), "TCP listeners")
			if c.Status != "FAIL" || !strings.Contains(c.Detail, "cannot read sockets: ") {
				t.Fatalf("socket result: %+v", c)
			}
			if strings.Contains(tc.name, "netlink") && c.Detail != "cannot read sockets: Cannot open netlink socket: Operation not permitted" {
				t.Fatalf("netlink detail: %+v", c)
			}
			if err := i.writeBaseline(); err == nil || !strings.Contains(err.Error(), "cannot read sockets: ") {
				t.Fatalf("baseline error: %v", err)
			}
		})
	}
}

func TestConfigAndKeysFailures(t *testing.T) {
	i := fixture(t, safeSS)
	if err := os.WriteFile(i.path("/etc/tor/torrc"), []byte("# %include /etc/tor/torrc.d/*.conf\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(i.homePath(".ssh", "authorized_keys"), 0666); err != nil {
		t.Fatal(err)
	}
	r := i.inspect()
	if find(t, r, "Tor include").Status != "FAIL" || find(t, r, "authorized_keys").Status != "FAIL" {
		t.Fatalf("got %+v", r)
	}
	if err := os.Chmod(i.homePath(".ssh", "authorized_keys"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.homePath(".ssh", "authorized_keys"), []byte("ssh-rsa AAAA old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if find(t, i.inspect(), "authorized_keys").Status != "FAIL" {
		t.Fatal("accepted RSA key")
	}
}

func TestCommandAndAllowlistErrors(t *testing.T) {
	i := fixture(t, safeSS)
	i.run = func(name string, args ...string) (string, error) { return "", errors.New("unavailable") }
	if find(t, i.inspect(), "TCP listeners").Status != "FAIL" {
		t.Fatal("accepted failed ss")
	}
	i = fixture(t, safeSS)
	if err := os.WriteFile(i.baselinePath(), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if find(t, i.inspect(), "TCP listeners").Status != "FAIL" {
		t.Fatal("accepted invalid allowlist")
	}
}

func TestBaselineIncludesExposedSSHButCannotAllowIt(t *testing.T) {
	i := fixture(t, safeSS+"LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
	if err := i.writeBaseline(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(i.baselinePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "0.0.0.0:22\n0.0.0.0:443\n" {
		t.Fatalf("baseline: %q", b)
	}
	if c := find(t, i.inspect(), "TCP listeners"); c.Status != "FAIL" {
		t.Fatalf("accepted exposed SSH: %+v", c)
	}
}

func TestExitAndNotification(t *testing.T) {
	i := fixture(t, safeSS)
	notified := 0
	original := i.run
	i.run = func(name string, args ...string) (string, error) {
		if name == "notify-send" {
			notified++
			return "", errors.New("no display")
		}
		return original(name, args...)
	}
	if code := execute([]string{"--notify"}, i); code != 0 || notified != 0 {
		t.Fatalf("healthy: code=%d notified=%d", code, notified)
	}
	if err := os.Remove(i.path("/etc/ufw/ufw.conf")); err != nil {
		t.Fatal(err)
	}
	if code := execute([]string{"--notify"}, i); code != 1 || notified != 1 {
		t.Fatalf("failure: code=%d notified=%d", code, notified)
	}
	if code := execute([]string{"--bad-option"}, i); code != 2 {
		t.Fatalf("usage code=%d", code)
	}
}
