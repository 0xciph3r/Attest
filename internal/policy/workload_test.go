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
		"wrong schema":     `{"schema":"attest.dev/measurement-policy/v1","workloads":[]}`,
		"unknown field":    wl(base + `,"gid":5`),
		"trailing data":    wl(base) + `{}`,
		"missing uid":      wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service"`),
		"root uid":         wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":0`),
		"invalid uid":      wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":4294967295`),
		"negative uid":     wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.service","uid":-1`),
		"no nodes":         wl(`"name":"api","nodes":[],"systemd_unit":"api.service","uid":1000`),
		"bad node":         wl(`"name":"api","nodes":["N1"],"systemd_unit":"api.service","uid":1000`),
		"duplicate node":   wl(`"name":"api","nodes":["n1","n1"],"systemd_unit":"api.service","uid":1000`),
		"wildcard node":    wl(`"name":"api","nodes":["*"],"systemd_unit":"api.service","uid":1000`),
		"bad name":         wl(`"name":"API","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"path in name":     wl(`"name":"a/b","nodes":["n1"],"systemd_unit":"api.service","uid":1000`),
		"not a service":    wl(`"name":"api","nodes":["n1"],"systemd_unit":"api.scope","uid":1000`),
		"slash in unit":    wl(`"name":"api","nodes":["n1"],"systemd_unit":"x/api.service","uid":1000`),
		"ttl too long":     wl(base + `,"ttl":"2h"`),
		"ttl too short":    wl(base + `,"ttl":"30s"`),
		"ttl unparseable":  wl(base + `,"ttl":"soon"`),
		"duplicate name":   `{"schema":"attest.dev/workload-policy/v1","workloads":[{` + base + `},{` + base + `}]}`,
		"ambiguous caller": `{"schema":"attest.dev/workload-policy/v1","workloads":[{` + base + `},{"name":"b","nodes":["n1"],"systemd_unit":"api.service","uid":1001}]}`,
	} {
		if _, err := ParseWorkload([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
