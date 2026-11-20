package agent

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCgroup(t *testing.T) {
	if p, err := parseCgroup([]byte("0::/system.slice/api.service\n")); err != nil || p != "/system.slice/api.service" {
		t.Fatalf("%q, %v", p, err)
	}
	for name, in := range map[string]string{
		"empty":            "",
		"no newline":       "0::/system.slice/api.service",
		"hybrid":           "1:name=systemd:/system.slice/api.service\n0::/system.slice/api.service\n",
		"hybrid v2 first":  "0::/system.slice/api.service\n1:name=systemd:/user.slice\n",
		"v1 only":          "12:memory:/system.slice/api.service\n",
		"relative":         "0::system.slice/api.service\n",
		"namespace escape": "0::/../../system.slice/api.service\n",
		"blank line":       "0::/system.slice/api.service\n\n",
		"wrong id":         "1::/system.slice/api.service\n",
		"oversized":        "0::/" + strings.Repeat("a", maxCgroupFile) + "\n",
		"nul":              "0::/system.slice/api.service\x00\n",
	} {
		p, err := parseCgroup([]byte(in))
		if err == nil {
			// Accepted paths must still be refused by serviceUnit.
			if _, uerr := serviceUnit(p); uerr == nil {
				t.Errorf("%s: accepted %q", name, p)
			}
			continue
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestServiceUnit(t *testing.T) {
	for path, want := range map[string]string{
		"/system.slice/api.service":                               "api.service",
		"/system.slice/getty@tty1.service":                        "getty@tty1.service",
		"/system.slice/system-getty.slice/getty@tty1.service":     "getty@tty1.service",
		"/system.slice/system-a.slice/system-a-b.slice/x.service": "x.service",
		"/system.slice/api.service/worker":                        "api.service",
		"/system.slice/api.service/other.service":                 "api.service",
		"/system.slice/api.service/sub/deeper":                    "api.service",
		"/system.slice/my-app_v2:x.service":                       "my-app_v2:x.service",
		"/system.slice/a\\x2db.service":                           "a\\x2db.service",
	} {
		got, err := serviceUnit(path)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", path, got, err)
		}
	}
}

// Every location other than a system service is refused, in particular
// those a non-root user can create or name.
func TestServiceUnitRejects(t *testing.T) {
	for _, path := range []string{
		"/",
		"",
		"/system.slice",
		"/system.slice/",
		"/system.slice/system-a.slice",
		// User managers run units the user names freely.
		"/user.slice/user-1000.slice/user@1000.service/app.slice/api.service",
		"/user.slice/user-1000.slice/user@1000.service",
		"/user.slice/user-1000.slice/session-3.scope",
		// Scopes: containers, transient sessions, systemd-run --scope.
		"/system.slice/docker-0123abcd.scope",
		"/system.slice/run-r1234.scope/api.service",
		"/machine.slice/libvirt-qemu-1.scope",
		// Slices outside system.slice.
		"/app.slice/api.service",
		"/init.scope",
		"/api.service",
		// Malformed or not a service.
		"/system.slice/api.socket",
		"/system.slice/api.timer",
		"/system.slice/api.service.d",
		"/system.slice/.service",
		"/system.slice/a b.service",
		"/system.slice/a/b.service",
		"/system.slice//api.service",
		"/system.slice/./api.service",
		"/system.slice/../api.service",
		"/system.slice/../system.slice/api.service",
		"system.slice/api.service",
		"//system.slice/api.service",
		"/system.slice/" + strings.Repeat("a", 248) + ".service",
		"/system.slice/api.service\n",
		"/system.slice/api\x00.service",
		"/System.slice/api.service",
	} {
		if u, err := serviceUnit(path); err == nil || !errors.Is(err, ErrNotService) {
			t.Errorf("%q: %q, %v", path, u, err)
		}
	}
}
