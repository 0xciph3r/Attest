package policy

import (
	"bytes"
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
