package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Result struct {
	Version int     `json:"version"`
	OK      bool    `json:"ok"`
	Checks  []Check `json:"checks"`
}

type runner func(string, ...string) (string, error)

type inspector struct {
	root string
	home string
	run  runner
}

func realRunner(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func (i inspector) path(p string) string {
	return filepath.Join(i.root, strings.TrimPrefix(p, string(filepath.Separator)))
}

func (i inspector) homePath(parts ...string) string {
	return i.path(filepath.Join(append([]string{i.home}, parts...)...))
}

func pass(name, detail string) Check { return Check{name, "PASS", detail} }
func fail(name, detail string) Check { return Check{name, "FAIL", detail} }
func skip(name, detail string) Check { return Check{name, "SKIP", detail} }

func (i inspector) file(name, path string, required ...string) Check {
	b, err := os.ReadFile(i.path(path))
	if err != nil {
		return fail(name, fmt.Sprintf("%s: %v", path, err))
	}
	for _, want := range required {
		if !hasDirective(string(b), want) {
			return fail(name, fmt.Sprintf("%s lacks active %q", path, want))
		}
	}
	return pass(name, path+" has required settings")
}

// Match active whole directives, allowing indentation and whitespace between fields.
func hasDirective(data, want string) bool {
	fields := strings.Fields(want)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.Join(strings.Fields(line), " ") == strings.Join(fields, " ") {
			return true
		}
	}
	return false
}

func (i inspector) services() []Check {
	var out []Check
	for _, service := range []string{"tor@default", "ssh", "ufw", "apt-daily-upgrade.timer"} {
		name := "service " + service
		state, err := i.run("systemctl", "is-active", service)
		if err != nil || strings.TrimSpace(state) != "active" {
			if state == "" {
				state = fmt.Sprint(err)
			}
			out = append(out, fail(name, "state: "+strings.TrimSpace(state)))
		} else {
			out = append(out, pass(name, "active"))
		}
	}
	return out
}

type listener struct{ address, port, process string }

func (l listener) String() string { return l.address + ":" + l.port }

func parseListeners(output string) ([]listener, error) {
	var out []listener
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			if strings.Contains(strings.ToLower(line), "netlink") || strings.Contains(strings.ToLower(line), "permission denied") {
				return nil, fmt.Errorf("%s", line)
			}
			return nil, fmt.Errorf("invalid ss output line: %q", line)
		}
		local := fields[3]
		n := strings.LastIndex(local, ":")
		if n < 1 || n == len(local)-1 {
			return nil, fmt.Errorf("unexpected ss address: %q", local)
		}
		address := strings.TrimPrefix(strings.TrimSuffix(local[:n], "]"), "[")
		l := listener{address: address, port: local[n+1:]}
		if p := strings.Index(line, "users:((\""); p >= 0 {
			name := line[p+len("users:((\""):]
			end := strings.IndexByte(name, '"')
			if end < 0 || end == 0 {
				return nil, fmt.Errorf("unexpected ss process: %q", line)
			}
			l.process = name[:end]
		}
		out = append(out, l)
	}
	return out, scanner.Err()
}

func isLoopback(addr string) bool {
	return addr == "localhost" || addr == "::1" || strings.HasPrefix(addr, "127.")
}

func (i inspector) baselinePath() string {
	return i.homePath(".config", "hardening-check", "allowed-listeners")
}

func (i inspector) allowed() (map[string]bool, error) {
	b, err := os.ReadFile(i.baselinePath())
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool)
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if len(strings.Fields(line)) != 1 || !validListenerRule(line) {
			return nil, fmt.Errorf("invalid allowlist line %d", n+1)
		}
		allowed[line] = true
	}
	return allowed, nil
}

func validListenerRule(rule string) bool {
	if strings.HasPrefix(rule, "process:") {
		return len(rule) > len("process:")
	}
	port := rule
	if strings.Contains(rule, ":") {
		n := strings.LastIndex(rule, ":")
		if n < 1 {
			return false
		}
		port = rule[n+1:]
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func listenerAllowed(l listener, allowed map[string]bool) bool {
	return allowed[l.String()] || allowed["*:"+l.port] || allowed[l.port] || l.process != "" && allowed["process:"+l.process]
}

func socketReadError(output string, err error) string {
	if strings.TrimSpace(output) != "" {
		return "cannot read sockets: " + strings.TrimSpace(output)
	}
	return "cannot read sockets: " + err.Error()
}

func (i inspector) listeners() Check {
	output, err := i.run("ss", "-ltnpH")
	if err != nil {
		return fail("TCP listeners", socketReadError(output, err))
	}
	ls, err := parseListeners(output)
	if err != nil {
		return fail("TCP listeners", "cannot read sockets: "+err.Error())
	}
	allowed, err := i.allowed()
	if err != nil {
		return fail("TCP listeners", "allowlist: "+err.Error())
	}
	localSSH := false
	var exposedSSH, other, unknown []string
	for _, l := range ls {
		if l.port == "22" {
			if l.address == "127.0.0.1" {
				localSSH = true
			}
			if !isLoopback(l.address) {
				exposedSSH = append(exposedSSH, l.String())
			}
		} else if !isLoopback(l.address) {
			other = append(other, l.String())
			if !listenerAllowed(l, allowed) {
				unknown = append(unknown, l.String())
			}
		}
	}
	sort.Strings(exposedSSH)
	sort.Strings(other)
	sort.Strings(unknown)
	detail := "127.0.0.1:22 listening"
	if !localSSH {
		detail = "127.0.0.1:22 absent"
	}
	if len(exposedSSH) > 0 {
		detail += "; exposed SSH: " + strings.Join(exposedSSH, ", ")
	}
	if len(other) > 0 {
		detail += "; other non-loopback TCP: " + strings.Join(other, ", ")
	}
	if len(unknown) > 0 {
		detail += "; not allowlisted: " + strings.Join(unknown, ", ")
	}
	if !localSSH || len(exposedSSH) > 0 || len(unknown) > 0 {
		return fail("TCP listeners", detail)
	}
	return pass("TCP listeners", detail)
}

func (i inspector) keys() Check {
	path := i.homePath(".ssh", "authorized_keys")
	info, err := os.Stat(path)
	if err != nil {
		return fail("authorized_keys", err.Error())
	}
	if info.Mode()&0022 != 0 {
		return fail("authorized_keys", "group/world writable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fail("authorized_keys", err.Error())
	}
	count := 0
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "ssh-ed25519" {
			return fail("authorized_keys", fmt.Sprintf("line %d is not an ssh-ed25519 key", n+1))
		}
		count++
	}
	return pass("authorized_keys", fmt.Sprintf("%d ed25519 keys; mode %04o", count, info.Mode().Perm()))
}

func (i inspector) inspect() Result {
	checks := i.services()
	checks = append(checks,
		i.file("UFW enabled", "/etc/ufw/ufw.conf", "ENABLED=yes"),
		i.file("SSH configuration", "/etc/ssh/sshd_config.d/10-hardening.conf", "ListenAddress 127.0.0.1", "PasswordAuthentication no", "ChannelTimeout session=10m"),
		i.file("Tor SSH onion", "/etc/tor/torrc.d/50-ssh-onion.conf", "HiddenServicePort 22 127.0.0.1:22"),
		i.file("Tor include", "/etc/tor/torrc", "%include /etc/tor/torrc.d/*.conf"),
		i.file("unattended upgrades", "/etc/apt/apt.conf.d/52hardening-unattended"),
		i.listeners(), i.keys(),
	)
	result := Result{Version: 1, OK: true, Checks: checks}
	for _, c := range checks {
		if c.Status == "FAIL" {
			result.OK = false
		}
	}
	return result
}

func (i inspector) writeBaseline() error {
	output, err := i.run("ss", "-ltnpH")
	if err != nil {
		return fmt.Errorf("%s", socketReadError(output, err))
	}
	ls, err := parseListeners(output)
	if err != nil {
		return fmt.Errorf("cannot read sockets: %w", err)
	}
	unique := make(map[string]string)
	for _, l := range ls {
		if !isLoopback(l.address) {
			if l.process != "" {
				key := "process:" + l.process
				if old, ok := unique[key]; !ok || l.String() < old {
					unique[key] = l.String()
				}
			} else {
				unique[l.String()] = ""
			}
		}
	}
	lines := make([]string, 0, len(unique))
	for l := range unique {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	path := i.baselinePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	var data bytes.Buffer
	for _, l := range lines {
		if unique[l] != "" {
			fmt.Fprintf(&data, "%s # %s\n", l, unique[l])
		} else {
			fmt.Fprintln(&data, l)
		}
	}
	return os.WriteFile(path, data.Bytes(), fs.FileMode(0600))
}
