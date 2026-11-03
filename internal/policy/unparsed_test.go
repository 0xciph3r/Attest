package policy

import (
	"bytes"
	"strings"
	"testing"
)

// Policies built without Parse have no validated form and must never admit
// or identify anything.
func TestUnparsedPoliciesFailClosed(t *testing.T) {
	ms := map[string]*Measurement{
		"nil":  nil,
		"zero": {},
		"literal": {
			Schema:     SchemaMeasurementV1,
			PCRs:       []uint32{0},
			References: []Reference{{Name: "a", PCRs: map[string]string{"0": v1}}},
		},
	}
	pcrs := map[uint32][]byte{0: bytes.Repeat([]byte{0xee}, 32)}
	for name, m := range ms {
		for _, in := range []map[uint32][]byte{nil, pcrs} {
			if ref, err := m.Evaluate(in); err == nil {
				t.Errorf("%s: admitted by %q", name, ref)
			}
		}
	}

	uid := uint32(1000)
	ws := map[string]*WorkloadPolicy{
		"nil":  nil,
		"zero": {},
		"no uid": {Schema: SchemaWorkloadV1, Workloads: []Workload{
			{Name: "a", Nodes: []string{"n1"}, SystemdUnit: "a.service"}}},
		"literal": {Schema: SchemaWorkloadV1, Workloads: []Workload{
			{Name: "a", Nodes: []string{"n1"}, SystemdUnit: "a.service", UID: &uid}}},
	}
	for name, p := range ws {
		if w, err := p.Match(Caller{"n1", "a.service", 1000}); err == nil {
			t.Errorf("%s: identified %v", name, w)
		}
	}
}

func TestDigestIgnoresHexCase(t *testing.T) {
	doc := `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[{"name":"a","pcrs":{"0":"` + strings.Repeat("ab", 32) + `"}}]}`
	a, err := ParseMeasurement([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseMeasurement([]byte(strings.ReplaceAll(doc, "ab", "AB")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Digest(), b.Digest()) {
		t.Fatal("hex case changed the digest of an identical policy")
	}
}
