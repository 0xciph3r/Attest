package policy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

const workloadDoc = `{"schema":"attest.dev/workload-policy/v1","workloads":[
	{"name":"payments-api","nodes":["node-a","node-b"],"systemd_unit":"payments-api.service","uid":1001,"ttl":"5m"},
	{"name":"ledger","nodes":["node-a"],"systemd_unit":"ledger@blue.service","uid":1002}]}`

func TestWorkloadMatch(t *testing.T) {
	p, err := ParseWorkload([]byte(workloadDoc))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		caller Caller
		want   string
	}{
		{"exact", Caller{"node-a", "payments-api.service", 1001}, "payments-api"},
		{"second node", Caller{"node-b", "payments-api.service", 1001}, "payments-api"},
		{"template instance", Caller{"node-a", "ledger@blue.service", 1002}, "ledger"},
		{"node not listed", Caller{"node-b", "ledger@blue.service", 1002}, ""},
		{"right unit wrong uid", Caller{"node-a", "payments-api.service", 1002}, ""},
		{"right uid wrong unit", Caller{"node-a", "ledger@blue.service", 1001}, ""},
		{"other instance", Caller{"node-a", "ledger@green.service", 1002}, ""},
		{"unknown node", Caller{"node-z", "payments-api.service", 1001}, ""},
	} {
		w, err := p.Match(tc.caller)
		switch {
		case tc.want == "" && !errors.Is(err, ErrWorkloadNotAllowed):
			t.Errorf("%s: got %v, %v; want denial", tc.name, w, err)
		case tc.want != "" && (err != nil || w.Name != tc.want):
			t.Errorf("%s: got %v, %v; want %s", tc.name, w, err, tc.want)
		}
	}
	w, _ := p.Match(Caller{"node-a", "payments-api.service", 1001})
	if w.Lifetime() != 5*time.Minute {
		t.Errorf("ttl %s", w.Lifetime())
	}
	w, _ = p.Match(Caller{"node-a", "ledger@blue.service", 1002})
	if w.Lifetime() != DefaultWorkloadTTL {
		t.Errorf("default ttl %s", w.Lifetime())
	}

	empty, err := ParseWorkload([]byte(`{"schema":"attest.dev/workload-policy/v1","workloads":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Match(Caller{"node-a", "payments-api.service", 1001}); !errors.Is(err, ErrWorkloadNotAllowed) {
		t.Fatalf("empty policy: %v", err)
	}
}

func TestWorkloadDigestIsCanonical(t *testing.T) {
	a, err := ParseWorkload([]byte(workloadDoc))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseWorkload([]byte(strings.ReplaceAll(workloadDoc, "\n\t", " ")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Digest(), b.Digest()) {
		t.Fatal("whitespace changed the digest")
	}
}

func TestWorkloadRejects(t *testing.T) {
	wl := func(fields string) string {
		return `{"schema":"attest.dev/workload-policy/v1","workloads":[{` + fields + `}]}`
	}
	base := `"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":1000`
	for name, doc := range map[string]string{
		"wrong schema":          `{"schema":"attest.dev/measurement-policy/v1","workloads":[]}`,
		"unknown field":         wl(base + `,"gid":5`),
		"trailing data":         wl(base) + `{}`,
		"missing uid":           wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service"`),
		"root uid":              wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":0`),
		"invalid uid":           wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":4294967295`),
		"negative uid":          wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":-1`),
		"no nodes":              wl(`"name":"api","nodes":[],"systemd_unit":"api.service","uid":1000`),
		"bad node":              wl(`"name":"api","nodes":["N1"],"systemd_unit":"api.service","uid":1000`),
		"duplicate node":        wl(`"name":"api","nodes":["n1","n1"],"systemd_unit":"api.service","uid":1000`),
		"wildcard node":         wl(`"name":"api","nodes":["*"],"systemd_unit":"api.service","uid":1000`),
		"bad name":              wl(`"name":"API","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"path in name":          wl(`"name":"a/b","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"not a service":         wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.scope","uid":1000`),
		"slash in unit":         wl(`"name":"api","nodes":["n1"],"systemd_unit":"x/api.service","uid":1000`),
		"ttl too long":          wl(base + `,"ttl":"2h"`),
		"ttl too short":         wl(base + `,"ttl":"30s"`),
		"ttl unparseable":       wl(base + `,"ttl":"soon"`),
		"duplicate name":        `{"schema":"attest.dev/workload-policy/v1","workloads":[{` + base + `},{` + base + `}]}`,
		"smuggled uid":          wl(base + `,"uid":0`),
		"case-variant uid":      wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","UID":1000`),
		"uid as string":         wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":"1000"`),
		"uid fractional":        wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":1000.5`),
		"uid overflow":          wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":4294967296`),
		"uid null":              wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":null`),
		"name too long":         wl(`"name":"` + strings.Repeat("a", 64) + `","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"empty name":            wl(`"name":"","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"leading dash":          wl(`"name":"-api","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"nodes null":            wl(`"name":"api","nodes":null,"systemd_unit":"api.service","uid":1000`),
		"empty node":            wl(`"name":"api","nodes":[""],"systemd_unit":"api.service","uid":1000`),
		"unit too long":         wl(`"name":"api","nodes":["n1"],"systemd_unit":"` + strings.Repeat("a", 248) + `.service","uid":1000`),
		"bare suffix":           wl(`"name":"api","nodes":["n1"],"systemd_unit":".service","uid":1000`),
		"unit newline":          wl(`"name":"api","nodes":["n1"],"systemd_unit":"api\n.service","uid":1000`),
		"unit space":            wl(`"name":"api","nodes":["n1"],"systemd_unit":"my api.service","uid":1000`),
		"unit unicode":          wl(`"name":"api","nodes":["n1"],"systemd_unit":"apі.service","uid":1000`),
		"unit empty":            wl(`"name":"api","nodes":["n1"],"systemd_unit":"","uid":1000`),
		"slice unit":            wl(`"name":"api","nodes":["n1"],"systemd_unit":"system.slice","uid":1000`),
		"ttl zero":              wl(base + `,"ttl":"0s"`),
		"ttl negative":          wl(base + `,"ttl":"-5m"`),
		"ttl just over":         wl(base + `,"ttl":"1h0m1s"`),
		"ttl number":            wl(base + `,"ttl":600`),
		"workloads object":      `{"schema":"attest.dev/workload-policy/v1","workloads":{}}`,
		"overlapping ambiguity": `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"a","nodes":["n1","n2"],"systemd_unit":"api.service","uid":1000},{"name":"b","nodes":["n3","n2"],"systemd_unit":"api.service","uid":1000}]}`,
		"ambiguous caller":      `{"schema":"attest.dev/workload-policy/v1","workloads":[{` + base + `},{"name":"b","nodes":["n1"],"systemd_unit":"api.service","uid":1001}]}`,
	} {
		if _, err := ParseWorkload([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestWorkloadBoundaries(t *testing.T) {
	wl := func(name, unit, ttl string) string {
		return `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"` + name + `","nodes":["n1"],"systemd_unit":"` + unit + `","uid":1000,"ttl":"` + ttl + `"}]}`
	}
	for name, doc := range map[string]string{
		"longest name": wl(strings.Repeat("a", 63), "api.service", "15m"),
		"longest unit": wl("api", strings.Repeat("a", 247)+".service", "15m"),
		"minimum ttl":  wl("api", "api.service", "1m"),
		"maximum ttl":  wl("api", "api.service", "1h"),
		"escaped unit": wl("api", `foo\\x2dbar.service`, "15m"),
		// The same service may be different workloads on different nodes.
		"same unit, disjoint nodes": `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"a","nodes":["n1"],"systemd_unit":"api.service","uid":1000},{"name":"b","nodes":["n2"],"systemd_unit":"api.service","uid":1000}]}`,
		"missing workloads":         `{"schema":"attest.dev/workload-policy/v1"}`,
	} {
		if _, err := ParseWorkload([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	p, err := ParseWorkload([]byte(workloadDoc))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Caller{
		"zero caller":     {},
		"empty unit":      {NodeID: "node-a", UID: 1001},
		"root":            {NodeID: "node-a", SystemdUnit: "payments-api.service"},
		"unit case":       {NodeID: "node-a", SystemdUnit: "Payments-api.service", UID: 1001},
		"unit prefix":     {NodeID: "node-a", SystemdUnit: "payments-api.service.d", UID: 1001},
		"node case":       {NodeID: "Node-a", SystemdUnit: "payments-api.service", UID: 1001},
		"node suffix":     {NodeID: "node-a.evil", SystemdUnit: "payments-api.service", UID: 1001},
		"template prefix": {NodeID: "node-a", SystemdUnit: "ledger@.service", UID: 1002},
	} {
		if w, err := p.Match(c); !errors.Is(err, ErrWorkloadNotAllowed) {
			t.Errorf("%s: matched %v", name, w)
		}
	}
	missing, _ := ParseWorkload([]byte(`{"schema":"attest.dev/workload-policy/v1"}`))
	if _, err := missing.Match(Caller{"n1", "api.service", 1000}); !errors.Is(err, ErrWorkloadNotAllowed) {
		t.Fatal("policy without workloads identified a caller")
	}
}
