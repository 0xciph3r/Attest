package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestIDRoundTrip(t *testing.T) {
	n, err := NodeID("attest.local", "node-1")
	if err != nil || n.String() != "spiffe://attest.local/node/node-1" {
		t.Fatalf("%v, %v", n, err)
	}
	w, err := WorkloadID("prod.example", "payments")
	if err != nil || w.String() != "spiffe://prod.example/workload/payments" {
		t.Fatalf("%v, %v", w, err)
	}
	for _, id := range []ID{n, w} {
		got, err := ParseID(id.String())
		if err != nil || got != id {
			t.Fatalf("ParseID(%s) = %+v, %v", id, got, err)
		}
	}
}

func TestIDRejects(t *testing.T) {
	for _, c := range []struct{ td, name string }{
		{"", "node-1"},
		{"Attest.local", "node-1"},
		{"attest..local", "node-1"},
		{".attest", "node-1"},
		{"attest.", "node-1"},
		{"attest local", "node-1"},
		{"attest.local:443", "node-1"},
		{strings.Repeat("a", 256), "node-1"},
		{"attest.local", ""},
		{"attest.local", "../ca"},
		{"attest.local", "node/1"},
		{"attest.local", "node%2f1"},
	} {
		if _, err := NodeID(c.td, c.name); !errors.Is(err, ErrInvalidID) {
			t.Errorf("NodeID(%q, %q): %v", c.td, c.name, err)
		}
	}
	for _, name := range []string{"", "Payments", "-payments", "pay/ments", strings.Repeat("a", 64)} {
		if _, err := WorkloadID("attest.local", name); !errors.Is(err, ErrInvalidID) {
			t.Errorf("WorkloadID(%q): %v", name, err)
		}
	}
	if _, err := newID("attest.local", Kind("admin"), "root"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("unknown kind: %v", err)
	}
}

func TestParseIDRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"spiffe://attest.local",
		"spiffe://attest.local/",
		"spiffe://attest.local/node",
		"spiffe://attest.local/node/",
		"spiffe://attest.local/node/node-1/",
		"spiffe://attest.local/node/node-1/extra",
		"spiffe://attest.local//node/node-1",
		"spiffe://attest.local/admin/root",
		"spiffe://attest.local/workload/Payments",
		"spiffe://attest.local/node/node%2D1",
		"spiffe://attest.local/node/../workload/x",
		"spiffe://attest.local/workload/./payments",
		"spiffe://user@attest.local/node/node-1",
		"spiffe://attest.local:8443/node/node-1",
		"spiffe://attest.local/node/node-1?x=1",
		"spiffe://attest.local/node/node-1?",
		"spiffe://attest.local/node/node-1#frag",
		"spiffe://ATTEST.local/node/node-1",
		"SPIFFE://attest.local/node/node-1",
		"https://attest.local/node/node-1",
		"spiffe:attest.local/node/node-1",
		"spiffe:///node/node-1",
		"spiffe://attest.local/node/node-1\x00",
		"spiffe://%61ttest.local/node/node-1",
	} {
		if id, err := ParseID(s); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ParseID(%q) = %+v, %v", s, id, err)
		}
	}
	if _, err := parseURL(nil); !errors.Is(err, ErrInvalidID) {
		t.Error("nil URL accepted")
	}
}
