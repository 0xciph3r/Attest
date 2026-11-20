package agent

import (
	"bytes"
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
)

// checkServicePath fails unless path names a system service as
// serviceUnit promises: /system.slice, then only slices, then unit.
func checkServicePath(t *testing.T, path, unit string) {
	t.Helper()
	comps := strings.Split(path, "/")
	i := slices.Index(comps, unit)
	if len(comps) < 3 || comps[0] != "" || comps[1] != "system.slice" || i < 2 {
		t.Fatalf("serviceUnit(%q) = %q outside system.slice", path, unit)
	}
	for _, c := range comps[2:i] {
		if name, ok := strings.CutSuffix(c, ".slice"); !ok || strings.Contains(name, "@") || !policy.ValidSystemdService(name+".service") {
			t.Fatalf("serviceUnit(%q) = %q under non-slice %q", path, unit, c)
		}
	}
	if !policy.ValidSystemdService(unit) || strings.HasSuffix(unit, ".slice") {
		t.Fatalf("serviceUnit(%q) = invalid unit %q", path, unit)
	}
}

func FuzzServiceUnit(f *testing.F) {
	for _, s := range []string{
		"/system.slice/api.service", "/system.slice/a.slice/b.slice/api.service/sub",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/api.service",
		"/system.slice/docker-1.scope", "/system.slice/../api.service", "/system.slice//api.service",
		"/system.slice/.slice/api.service", "/", "", "system.slice/api.service", "/system.slice/a@b.service",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		unit, err := serviceUnit(path)
		if err == nil {
			checkServicePath(t, path, unit)
		}
	})
}

func FuzzParseCgroup(f *testing.F) {
	for _, s := range []string{
		"0::/system.slice/api.service\n", "0::/\n", "0::/system.slice/api.service",
		"12:cpu:/x\n0::/system.slice/api.service\n", "0::/a\n0::/b\n", "0::relative\n", "1::/x\n",
		"0::/system.slice/api.service\n\n", "",
		"0::/system.slice/" + strings.Repeat("a", maxCgroupFile) + ".service\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		path, err := parseCgroup(raw)
		if err != nil {
			return
		}
		if len(raw) > maxCgroupFile || !bytes.HasPrefix(raw, []byte("0::/")) ||
			bytes.Count(raw, []byte("\n")) != 1 || raw[len(raw)-1] != '\n' {
			t.Fatalf("parseCgroup accepted %q", raw)
		}
		if "0::"+path+"\n" != string(raw) {
			t.Fatalf("parseCgroup(%q) = %q", raw, path)
		}
		if unit, err := serviceUnit(path); err == nil {
			checkServicePath(t, path, unit)
		}
	})
}

// FuzzCallerLimiter drives the limiter with arbitrary callers and clock
// steps, including backwards ones, and checks no caller is granted more
// than its burst plus what the elapsed time refills.
func FuzzCallerLimiter(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 10, 0, 246, 0, 10, 0, 246, 0, 10, 0, 246, 1, 0, 1, 0})
	f.Add(bytes.Repeat([]byte{3, 1}, 64))
	f.Fuzz(func(t *testing.T, ops []byte) {
		l := newCallerLimiter()
		base := time.Unix(1_700_000_000, 0)
		now := base
		type key struct {
			unit string
			uid  uint32
		}
		granted := map[key]int{}
		first, latest := map[key]time.Time{}, map[key]time.Time{}
		for i := 0; i+1 < len(ops); i += 2 {
			k := key{[]string{"a.service", "b.service"}[ops[i]&1], uint32(ops[i]>>1) & 1}
			// Steps of -12.8s to +12.7s in 100ms units.
			now = now.Add(time.Duration(int8(ops[i+1])) * 100 * time.Millisecond)
			if _, ok := first[k]; !ok {
				first[k] = now
			}
			if now.After(latest[k]) {
				latest[k] = now
			}
			if l.allow(k.unit, k.uid, now) {
				granted[k]++
			}
			limit := callerBurst + callerRate*latest[k].Sub(first[k]).Seconds()
			if float64(granted[k]) > limit+1e-9 {
				t.Fatalf("%v granted %d, limit %.2f", k, granted[k], limit)
			}
		}
		if len(l.buckets) > maxCallers {
			t.Fatalf("%d buckets", len(l.buckets))
		}
	})
}

// FuzzCheckIdentity feeds the checks the agent applies to what attestd
// returns a choice of genuine and wrong certificates and bundles, with
// arbitrary byte corruption. Fuzz workers are separate processes with their
// own CA, so inputs select certificates rather than carry them.
func FuzzCheckIdentity(f *testing.F) {
	e := newEnv(f)
	a := e.agent()
	key := p256(f)
	csr, err := x509.ParseCertificateRequest(csrFor(f, key))
	if err != nil {
		f.Fatal(err)
	}
	other, err := identity.Init(f.TempDir(), identity.Options{TrustDomain: td, Now: e.clk.Now})
	if err != nil {
		f.Fatal(err)
	}
	n1, _ := identity.NodeID(td, "n1")
	n2, _ := identity.NodeID(td, "n2")
	wl, _ := identity.WorkloadID(td, "api")
	srv, _ := identity.ServerID(td, "attestd")
	nodeKey, otherKey := e.tpm.key.Key.Public(), p256(f).Public()
	certs := [][]byte{
		issue(f, e.ca, n1, nodeKey),      // 0: the genuine node identity
		issue(f, e.ca, wl, key.Public()), // 1: the genuine workload identity
		issue(f, e.ca, n2, nodeKey),
		issue(f, e.ca, n1, otherKey),
		issue(f, e.ca, wl, otherKey),
		issue(f, e.ca, n1, key.Public()),
		issue(f, e.ca, wl, nodeKey),
		issue(f, e.ca, srv, nodeKey),
		issue(f, e.ca, srv, key.Public()),
		issue(f, other, n1, nodeKey),
		issue(f, other, wl, key.Public()),
		e.ca.Bundle()[0].Raw,
	}
	bundles := [][]byte{e.ca.Bundle()[0].Raw, other.Bundle()[0].Raw, certs[0], certs[1]}
	for c := range len(certs) {
		for b := range len(bundles) {
			f.Add(uint8(c), uint8(b), uint16(0), byte(0)) //nolint:gosec // small
		}
	}
	f.Add(uint8(0), uint8(0), uint16(100), byte(1))
	f.Add(uint8(1), uint8(0), uint16(400), byte(0x80))
	f.Fuzz(func(t *testing.T, c, b uint8, pos uint16, flip byte) {
		cert := slices.Clone(certs[int(c)%len(certs)])
		ca := slices.Clone(bundles[int(b)%len(bundles)])
		// Corrupt the certificate, or the bundle when pos is odd.
		target := cert
		if pos&1 == 1 {
			target = ca
		}
		target[int(pos>>1)%len(target)] ^= flip
		id := &attestv1.X509Identity{Certificate: cert, Bundle: [][]byte{ca}}
		if _, _, err := a.checkNodeIdentity(id); err == nil && !bytes.Equal(cert, certs[0]) {
			t.Fatalf("node check accepted certificate %d, bundle %d, flip %x at %d", c, b, flip, pos)
		}
		if got, err := a.checkWorkloadIdentity(id, csr); err == nil {
			if !bytes.Equal(cert, certs[1]) || got.GetSpiffeId() != wl.String() {
				t.Fatalf("workload check accepted certificate %d, bundle %d, flip %x at %d as %q", c, b, flip, pos, got.GetSpiffeId())
			}
		}
	})
}
