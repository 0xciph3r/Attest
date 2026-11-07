package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func opts(c *clock) Options { return Options{TrustDomain: "attest.local", Now: c.Now} }

func newCAInDir(t *testing.T) (*CA, string, *clock) {
	t.Helper()
	dir := t.TempDir()
	clk := &clock{now: t0}
	c, err := Init(dir, opts(clk))
	if err != nil {
		t.Fatal(err)
	}
	return c, dir, clk
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func must(id ID, err error) ID {
	if err != nil {
		panic(err)
	}
	return id
}

func issue(t *testing.T, c *CA, id ID, ttl time.Duration) *Issued {
	t.Helper()
	is, err := c.Issue(IssueRequest{ID: id, PublicKey: p256(t).Public(), TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func TestCALifecycle(t *testing.T) {
	c, dir, clk := newCAInDir(t)
	for f, mode := range map[string]os.FileMode{CAFile: 0o600, BundleFile: 0o644} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	if !c.Cert().IsCA || c.Cert().MaxPathLen != 0 || !c.Cert().MaxPathLenZero || c.TrustDomain() != "attest.local" {
		t.Fatalf("CA cert %+v", c.Cert())
	}
	if bundle, _ := os.ReadFile(filepath.Join(dir, BundleFile)); !bytes.Equal(bundle, c.BundlePEM()) {
		t.Fatal("bundle file differs from BundlePEM")
	}
	l, err := Load(dir, opts(clk))
	if err != nil || !l.Cert().Equal(c.Cert()) || len(l.Bundle()) != 1 {
		t.Fatalf("Load: %v", err)
	}

	node := must(NodeID("attest.local", "node-1"))
	wl := must(WorkloadID("attest.local", "payments"))
	n := issue(t, l, node, time.Hour)
	if len(n.Serial) != 32 || n.Serial != strings.ToLower(n.Serial) || n.Cert.SerialNumber.Text(16) != strings.TrimLeft(n.Serial, "0") {
		t.Fatalf("serial %q", n.Serial)
	}
	if !n.Cert.NotAfter.Equal(t0.Add(time.Hour)) || !n.Cert.NotBefore.Equal(t0.Add(-clockSkew)) {
		t.Fatalf("validity %s - %s", n.Cert.NotBefore, n.Cert.NotAfter)
	}
	if id, err := Verify(l.Bundle(), "attest.local", n.Cert, t0, x509.ExtKeyUsageClientAuth); err != nil || id != node {
		t.Fatalf("Verify node: %v, %v", id, err)
	}
	// Node identities authenticate the agent to the control plane; they
	// are not server certificates.
	if _, err := Verify(l.Bundle(), "attest.local", n.Cert, t0, x509.ExtKeyUsageServerAuth); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("node cert as server: %v", err)
	}
	w := issue(t, l, wl, MaxTTL)
	for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if id, err := Verify(l.Bundle(), "attest.local", w.Cert, t0, u); err != nil || id != wl {
			t.Fatalf("Verify workload: %v, %v", id, err)
		}
	}
	if n.Serial == w.Serial {
		t.Fatal("serials repeat")
	}

	// Rotation keeps identities from the previous CA valid; a second
	// rotation drops it.
	clk.now = t0.Add(time.Minute)
	r1, err := Rotate(dir, opts(clk))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Cert().Equal(c.Cert()) || len(r1.Bundle()) != 2 || !r1.Bundle()[1].Equal(c.Cert()) {
		t.Fatal("rotation did not replace the CA")
	}
	n2 := issue(t, r1, node, time.Hour)
	if err := n2.Cert.CheckSignatureFrom(c.Cert()); err == nil {
		t.Fatal("new identity signed by the old CA")
	}
	l, err = Load(dir, opts(clk))
	if err != nil || !l.Cert().Equal(r1.Cert()) || len(l.Bundle()) != 2 {
		t.Fatalf("Load after rotate: %v", err)
	}
	for _, is := range []*Issued{n, n2} {
		if _, err := Verify(l.Bundle(), "attest.local", is.Cert, clk.now, x509.ExtKeyUsageClientAuth); err != nil {
			t.Fatalf("after rotation: %v", err)
		}
	}
	if _, err := Rotate(dir, opts(clk)); err != nil {
		t.Fatal(err)
	}
	l, err = Load(dir, opts(clk))
	if err != nil || len(l.Bundle()) != 2 || !l.Bundle()[1].Equal(r1.Cert()) {
		t.Fatalf("second rotation: %v", err)
	}
	if _, err := Verify(l.Bundle(), "attest.local", n.Cert, clk.now, x509.ExtKeyUsageClientAuth); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("identity from a dropped CA: %v", err)
	}
	if _, err := Verify(l.Bundle(), "attest.local", n2.Cert, clk.now, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("identity from the previous CA: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

func TestInitRefuses(t *testing.T) {
	clk := &clock{now: t0}
	for _, f := range []string{CAFile, BundleFile} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, f), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Init(dir, opts(clk)); !errors.Is(err, ErrCAExists) {
			t.Fatalf("%s exists: %v", f, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, f)); string(b) != "keep" {
			t.Fatalf("%s overwritten", f)
		}
	}
	// A dangling symlink is an existing file too.
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(dir, CAFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir, opts(clk)); !errors.Is(err, ErrCAExists) {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := Init(t.TempDir(), Options{TrustDomain: "Bad Domain"}); err == nil {
		t.Fatal("invalid trust domain accepted")
	}
	if _, err := Init(filepath.Join(t.TempDir(), "missing"), opts(clk)); err == nil {
		t.Fatal("missing directory accepted")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(open, opts(clk)); !errors.Is(err, ErrCAInvalid) {
		t.Fatalf("world-writable directory: %v", err)
	}

	// A failing entropy source leaves nothing behind.
	dir = t.TempDir()
	o := opts(clk)
	o.Rand = errReader{}
	if _, err := Init(dir, o); err == nil {
		t.Fatal("Init succeeded without entropy")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

// caFile builds a CA file from a certificate template signed by itself.
func caFile(t *testing.T, tmpl *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
}

func caTemplate(td string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		URIs:      []*url.URL{{Scheme: "spiffe", Host: td}},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
}

func TestLoadRejects(t *testing.T) {
	type env struct {
		t   *testing.T
		dir string
		ca  *CA
		clk *clock
	}
	write := func(e *env, name string, b []byte) {
		e.t.Helper()
		p := filepath.Join(e.dir, name)
		_ = os.Chmod(p, 0o600)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			e.t.Fatal(err)
		}
	}
	read := func(e *env, name string) []byte {
		b, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil {
			e.t.Fatal(err)
		}
		return b
	}
	// selfCA writes a CA file from tmpl and a matching bundle.
	selfCA := func(e *env, tmpl *x509.Certificate, key crypto.Signer) {
		b := caFile(e.t, tmpl, key)
		write(e, CAFile, b)
		blk, _ := pem.Decode(b)
		write(e, BundleFile, pem.EncodeToMemory(blk))
	}
	otherCA := func(e *env, td string) *CA {
		c, err := Init(e.t.TempDir(), Options{TrustDomain: td, Now: e.clk.Now})
		if err != nil {
			e.t.Fatal(err)
		}
		return c
	}
	tests := []struct {
		name   string
		mutate func(e *env)
		want   error // nil: any error
	}{
		{"missing CA file", func(e *env) { _ = os.Remove(filepath.Join(e.dir, CAFile)) }, ErrCAInvalid},
		{"missing bundle", func(e *env) { _ = os.Remove(filepath.Join(e.dir, BundleFile)) }, ErrCAInvalid},
		{"key readable by group", func(e *env) { _ = os.Chmod(filepath.Join(e.dir, CAFile), 0o640) }, ErrCAInvalid},
		{"key readable by others", func(e *env) { _ = os.Chmod(filepath.Join(e.dir, CAFile), 0o604) }, ErrCAInvalid},
		{"bundle writable by group", func(e *env) { _ = os.Chmod(filepath.Join(e.dir, BundleFile), 0o664) }, ErrCAInvalid},
		{"directory writable by others", func(e *env) { _ = os.Chmod(e.dir, 0o703) }, ErrCAInvalid},
		{"CA file is a symlink", func(e *env) {
			src := filepath.Join(e.t.TempDir(), "ca.pem")
			if err := os.WriteFile(src, read(e, CAFile), 0o600); err != nil {
				e.t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(e.dir, CAFile))
			_ = os.Symlink(src, filepath.Join(e.dir, CAFile))
		}, ErrCAInvalid},
		{"bundle is a symlink", func(e *env) {
			src := filepath.Join(e.t.TempDir(), "bundle.pem")
			if err := os.WriteFile(src, read(e, BundleFile), 0o644); err != nil {
				e.t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(e.dir, BundleFile))
			_ = os.Symlink(src, filepath.Join(e.dir, BundleFile))
		}, ErrCAInvalid},
		{"CA file is a directory", func(e *env) {
			_ = os.Remove(filepath.Join(e.dir, CAFile))
			_ = os.Mkdir(filepath.Join(e.dir, CAFile), 0o700)
		}, ErrCAInvalid},
		{"empty CA file", func(e *env) { write(e, CAFile, nil) }, ErrCAInvalid},
		{"garbage CA file", func(e *env) { write(e, CAFile, []byte("not pem")) }, ErrCAInvalid},
		{"oversized CA file", func(e *env) { write(e, CAFile, bytes.Repeat([]byte("\n"), maxFile+1)) }, ErrCAInvalid},
		{"truncated CA file", func(e *env) { b := read(e, CAFile); write(e, CAFile, b[:len(b)/2]) }, ErrCAInvalid},
		{"trailing data", func(e *env) { write(e, CAFile, append(read(e, CAFile), "junk"...)) }, ErrCAInvalid},
		{"key only", func(e *env) {
			_, rest := pem.Decode(read(e, CAFile))
			write(e, CAFile, rest)
		}, ErrCAInvalid},
		{"certificate only", func(e *env) {
			blk, _ := pem.Decode(read(e, CAFile))
			write(e, CAFile, pem.EncodeToMemory(blk))
		}, ErrCAInvalid},
		{"two certificates", func(e *env) {
			blk, _ := pem.Decode(read(e, CAFile))
			write(e, CAFile, append(pem.EncodeToMemory(blk), read(e, CAFile)...))
		}, ErrCAInvalid},
		{"two keys", func(e *env) {
			_, rest := pem.Decode(read(e, CAFile))
			write(e, CAFile, append(read(e, CAFile), rest...))
		}, ErrCAInvalid},
		{"PEM headers", func(e *env) {
			blk, rest := pem.Decode(read(e, CAFile))
			blk.Headers = map[string]string{"Proc-Type": "4,ENCRYPTED"}
			write(e, CAFile, append(pem.EncodeToMemory(blk), rest...))
		}, ErrCAInvalid},
		{"unexpected block", func(e *env) {
			write(e, CAFile, append(read(e, CAFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})...))
		}, ErrCAInvalid},
		{"key of another CA", func(e *env) {
			blk, _ := pem.Decode(read(e, CAFile))
			o := otherCA(e, "attest.local")
			pk, _ := x509.MarshalPKCS8PrivateKey(o.signer)
			write(e, CAFile, append(pem.EncodeToMemory(blk), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...))
		}, ErrCAInvalid},
		{"CA of another trust domain", func(e *env) {
			dir := e.t.TempDir()
			if _, err := Init(dir, Options{TrustDomain: "other.local", Now: e.clk.Now}); err != nil {
				e.t.Fatal(err)
			}
			for _, f := range []string{CAFile, BundleFile} {
				b, _ := os.ReadFile(filepath.Join(dir, f))
				write(e, f, b)
			}
		}, ErrCAInvalid},
		{"RSA CA key", func(e *env) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				e.t.Fatal(err)
			}
			selfCA(e, caTemplate("attest.local"), k)
		}, ErrCAInvalid},
		{"P-384 CA key", func(e *env) {
			k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			selfCA(e, caTemplate("attest.local"), k)
		}, ErrCAInvalid},
		{"not a CA", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.IsCA, tmpl.MaxPathLenZero = false, false
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA may issue intermediates", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.MaxPathLenZero, tmpl.MaxPathLen = false, -1
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA without certSign", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA without trust domain", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.URIs = nil
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA with workload ID", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.URIs = []*url.URL{{Scheme: "spiffe", Host: "attest.local", Path: "/workload/x"}}
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA with DNS name", func(e *env) {
			tmpl := caTemplate("attest.local")
			tmpl.DNSNames = []string{"attest.local"}
			selfCA(e, tmpl, p256(e.t))
		}, ErrCAInvalid},
		{"CA signed by another key", func(e *env) {
			parent := caTemplate("attest.local")
			pk := p256(e.t)
			child := caTemplate("attest.local")
			key := p256(e.t)
			der, err := x509.CreateCertificate(rand.Reader, child, parent, key.Public(), pk)
			if err != nil {
				e.t.Fatal(err)
			}
			kb, _ := x509.MarshalPKCS8PrivateKey(key)
			c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			write(e, CAFile, append(c, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})...))
			write(e, BundleFile, c)
		}, ErrCAInvalid},
		{"expired CA", func(e *env) { e.clk.now = e.ca.Cert().NotAfter.Add(time.Second) }, ErrCAExpired},
		{"CA not yet valid", func(e *env) { e.clk.now = e.ca.Cert().NotBefore.Add(-time.Second) }, ErrCAExpired},
		{"empty bundle", func(e *env) { write(e, BundleFile, nil) }, ErrCAInvalid},
		{"bundle without the current CA", func(e *env) { write(e, BundleFile, otherCA(e, "attest.local").BundlePEM()) }, ErrCAInvalid},
		{"current CA not first", func(e *env) {
			write(e, BundleFile, append(otherCA(e, "attest.local").BundlePEM(), read(e, BundleFile)...))
		}, ErrCAInvalid},
		{"three CAs", func(e *env) {
			b := read(e, BundleFile)
			b = append(b, otherCA(e, "attest.local").BundlePEM()...)
			write(e, BundleFile, append(b, otherCA(e, "attest.local").BundlePEM()...))
		}, ErrCAInvalid},
		{"duplicate bundle CA", func(e *env) { b := read(e, BundleFile); write(e, BundleFile, append(b, b...)) }, ErrCAInvalid},
		{"bundle CA of another trust domain", func(e *env) {
			write(e, BundleFile, append(read(e, BundleFile), otherCA(e, "other.local").BundlePEM()...))
		}, ErrCAInvalid},
		{"bundle holds a leaf", func(e *env) {
			is := issue(e.t, e.ca, must(NodeID("attest.local", "node-1")), time.Hour)
			write(e, BundleFile, append(read(e, BundleFile), encodeCerts([]*x509.Certificate{is.Cert})...))
		}, ErrCAInvalid},
		{"bundle holds a key", func(e *env) { write(e, BundleFile, read(e, CAFile)) }, ErrCAInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca, dir, clk := newCAInDir(t)
			e := &env{t: t, dir: dir, ca: ca, clk: clk}
			tc.mutate(e)
			c, err := Load(dir, opts(clk))
			if err == nil || c != nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := Load(t.TempDir(), Options{TrustDomain: ""}); err == nil {
		t.Fatal("empty trust domain accepted")
	}
}

func TestRotate(t *testing.T) {
	// An expired CA can be rotated; that is how it is recovered.
	c, dir, clk := newCAInDir(t)
	clk.now = c.Cert().NotAfter.Add(time.Hour)
	if _, err := Load(dir, opts(clk)); !errors.Is(err, ErrCAExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := Rotate(dir, opts(clk)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, opts(clk)); err != nil {
		t.Fatal(err)
	}

	// An invalid CA is not rotated, and nothing changes.
	_, dir, clk = newCAInDir(t)
	if err := os.Chmod(filepath.Join(dir, CAFile), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, BundleFile))
	if _, err := Rotate(dir, opts(clk)); !errors.Is(err, ErrCAInvalid) {
		t.Fatalf("got %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, BundleFile)); !bytes.Equal(before, after) {
		t.Fatal("bundle changed")
	}
	if _, err := Rotate(t.TempDir(), opts(clk)); err == nil {
		t.Fatal("rotated an empty directory")
	}

	// Failing entropy leaves the CA as it was.
	c, dir, clk = newCAInDir(t)
	o := opts(clk)
	o.Rand = errReader{}
	if _, err := Rotate(dir, o); err == nil {
		t.Fatal("rotated without entropy")
	}
	if l, err := Load(dir, opts(clk)); err != nil || !l.Cert().Equal(c.Cert()) || len(l.Bundle()) != 1 {
		t.Fatalf("CA changed: %v", err)
	}

	// A crash after the bundle is replaced but before the key leaves a
	// loadable CA whose bundle also trusts the lost successor.
	c, dir, clk = newCAInDir(t)
	succ, _, err := newCA(c.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir, BundleFile, encodeCerts([]*x509.Certificate{c.Cert(), succ.Cert()}), 0o644, true); err != nil {
		t.Fatal(err)
	}
	if l, err := Load(dir, opts(clk)); err != nil || !l.Cert().Equal(c.Cert()) {
		t.Fatalf("after partial rotation: %v", err)
	}
	r, err := Rotate(dir, opts(clk))
	if err != nil || len(r.Bundle()) != 2 || !r.Bundle()[1].Equal(c.Cert()) {
		t.Fatalf("rotation after a partial one: %v", err)
	}
}

func TestIssueRejects(t *testing.T) {
	c, _, clk := newCAInDir(t)
	node := must(NodeID("attest.local", "node-1"))
	good := p256(t).Public()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)} //nolint:staticcheck // deliberately invalid
	var nilKey *ecdsa.PublicKey
	for name, req := range map[string]IssueRequest{
		"other trust domain": {ID: must(NodeID("other.local", "node-1")), PublicKey: good, TTL: time.Hour},
		"zero ID":            {PublicKey: good, TTL: time.Hour},
		"forged ID":          {ID: ID{TrustDomain: "attest.local", Kind: KindNode, Name: "../x"}, PublicKey: good, TTL: time.Hour},
		"unknown kind":       {ID: ID{TrustDomain: "attest.local", Kind: "admin", Name: "root"}, PublicKey: good, TTL: time.Hour},
		"zero TTL":           {ID: node, PublicKey: good},
		"negative TTL":       {ID: node, PublicKey: good, TTL: -time.Hour},
		"TTL over maximum":   {ID: node, PublicKey: good, TTL: MaxTTL + time.Nanosecond},
		"no key":             {ID: node, TTL: time.Hour},
		"nil ECDSA key":      {ID: node, PublicKey: nilKey, TTL: time.Hour},
		"RSA key":            {ID: node, PublicKey: rk.Public(), TTL: time.Hour},
		"P-384 key":          {ID: node, PublicKey: p384.Public(), TTL: time.Hour},
		"Ed25519 key":        {ID: node, PublicKey: edPub, TTL: time.Hour},
		"off-curve key":      {ID: node, PublicKey: offCurve, TTL: time.Hour},
		"private key":        {ID: node, PublicKey: p256(t), TTL: time.Hour},
	} {
		if is, err := c.Issue(req); !errors.Is(err, ErrIssue) || is != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Validity never exceeds the CA's.
	clk.now = c.Cert().NotAfter.Add(-time.Minute)
	is := issue(t, c, node, time.Hour)
	if !is.Cert.NotAfter.Equal(c.Cert().NotAfter) {
		t.Fatalf("not clamped: %s", is.Cert.NotAfter)
	}
	clk.now = c.Cert().NotAfter
	if _, err := c.Issue(IssueRequest{ID: node, PublicKey: good, TTL: time.Hour}); !errors.Is(err, ErrCAExpired) {
		t.Fatalf("expired CA: %v", err)
	}
	clk.now = c.Cert().NotBefore
	if is := issue(t, c, node, time.Hour); is.Cert.NotBefore.Before(c.Cert().NotBefore) {
		t.Fatalf("starts before the CA: %s", is.Cert.NotBefore)
	}

	clk.now = t0
	c.opts.Rand = errReader{}
	if _, err := c.Issue(IssueRequest{ID: node, PublicKey: good, TTL: time.Hour}); err == nil {
		t.Fatal("issued without entropy")
	}
	c.opts.Rand = bytes.NewReader(make([]byte, 16))
	if _, err := c.Issue(IssueRequest{ID: node, PublicKey: good, TTL: time.Hour}); err == nil {
		t.Fatal("issued a zero serial")
	}
	c.opts.Rand = bytes.NewReader(bytes.Repeat([]byte{0xff}, 16))
	is, err = c.Issue(IssueRequest{ID: node, PublicKey: good, TTL: time.Hour})
	if err != nil || is.Cert.SerialNumber.Sign() <= 0 || is.Serial != "7fffffffffffffffffffffffffffffff" {
		t.Fatalf("high serial: %v %v", is, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	c, _, clk := newCAInDir(t)
	node := must(NodeID("attest.local", "node-1"))
	n := issue(t, c, node, time.Hour)
	// sign issues an arbitrary leaf from the CA's key.
	sign := func(t *testing.T, mod func(*x509.Certificate)) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(42), URIs: []*url.URL{node.URL()},
			NotBefore: t0.Add(-time.Minute), NotAfter: t0.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, p256(t).Public(), c.signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	if _, err := Verify(c.Bundle(), "attest.local", sign(t, func(*x509.Certificate) {}), t0, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("control leaf: %v", err)
	}
	impostor, err := Init(t.TempDir(), opts(clk))
	if err != nil {
		t.Fatal(err)
	}
	other, err := Init(t.TempDir(), Options{TrustDomain: "other.local", Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	otherLeaf := issue(t, other, must(NodeID("other.local", "node-1")), time.Hour)
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name   string
		bundle []*x509.Certificate
		td     string
		leaf   *x509.Certificate
		now    time.Time
	}{
		{"nil leaf", c.Bundle(), "attest.local", nil, t0},
		{"empty bundle", nil, "attest.local", n.Cert, t0},
		{"same trust domain, other CA", impostor.Bundle(), "attest.local", n.Cert, t0},
		{"issued by an impostor CA", c.Bundle(), "attest.local", issue(t, impostor, node, time.Hour).Cert, t0},
		{"other trust domain's CA trusted", append(c.Bundle(), other.Bundle()...), "attest.local", otherLeaf.Cert, t0},
		{"expired", c.Bundle(), "attest.local", n.Cert, n.Cert.NotAfter.Add(time.Second)},
		{"not yet valid", c.Bundle(), "attest.local", n.Cert, n.Cert.NotBefore.Add(-time.Second)},
		{"CA certificate as leaf", c.Bundle(), "attest.local", c.Cert(), t0},
		{"no URI", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) { c.URIs = nil }), t0},
		{"two URIs", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.URIs = append(c.URIs, must(WorkloadID("attest.local", "payments")).URL())
		}), t0},
		{"DNS SAN", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) { c.DNSNames = []string{"node-1"} }), t0},
		{"IP SAN", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} }), t0},
		{"non-SPIFFE URI", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.URIs = []*url.URL{mustURL("https://attest.local/node/node-1")}
		}), t0},
		{"non-canonical URI", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.URIs = []*url.URL{mustURL("spiffe://attest.local/node/node-1?x")}
		}), t0},
		{"trust domain ID", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "attest.local"}}
		}), t0},
		{"leaf for another trust domain", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.URIs = []*url.URL{must(NodeID("other.local", "node-1")).URL()}
		}), t0},
		{"no client auth", c.Bundle(), "attest.local", sign(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}), t0},
		{"intermediate CA issued it", c.Bundle(), "attest.local", func() *x509.Certificate {
			key := p256(t)
			tmpl := caTemplate("attest.local")
			der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.signer)
			if err != nil {
				t.Fatal(err)
			}
			imc, _ := x509.ParseCertificate(der)
			leaf := &x509.Certificate{SerialNumber: big.NewInt(7), URIs: []*url.URL{node.URL()},
				NotBefore: t0.Add(-time.Minute), NotAfter: t0.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			der, err = x509.CreateCertificate(rand.Reader, leaf, imc, p256(t).Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			lc, _ := x509.ParseCertificate(der)
			return lc
		}(), t0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if id, err := Verify(tc.bundle, tc.td, tc.leaf, tc.now, x509.ExtKeyUsageClientAuth); !errors.Is(err, ErrUntrusted) {
				t.Fatalf("got %v, %v", id, err)
			}
		})
	}
}
