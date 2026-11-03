//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyValidate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, doc string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pcr := strings.Repeat("ab", 32)
	good := write("good.json", `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0,7],
		"references":[{"name":"fw-1.2","pcrs":{"0":"`+pcr+`","7":"`+pcr+`"}}]}`)
	expect(t, ctl(t, "policy", "validate", good), 0, "fw-1.2")

	dev := write("dev.json", `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[],
		"allow_development_roots":true}`)
	r := ctl(t, "policy", "validate", dev)
	expect(t, r, 0, "admits no machine")
	expect(t, r, 0, "allow_development_roots")

	partial := write("partial.json", `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0,7],
		"references":[{"name":"fw","pcrs":{"0":"`+pcr+`"}}]}`)
	expect(t, ctl(t, "policy", "validate", partial), 0, "PCRs [7] are quoted and replayed but accept any value")

	for name, doc := range map[string]string{
		"unknown field":    `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[],"pcr":[1]}`,
		"PCR not selected": `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[{"name":"x","pcrs":{"7":"` + pcr + `"}}]}`,
		"trailing data":    `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[]} {}`,
		"not json":         `pcrs: [0]`,
		"duplicate key":    `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[],"allow_development_roots":false,"allow_development_roots":true}`,
		"case-variant key": `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[],"Allow_Development_Roots":true}`,
		// The dispatcher and the parser must agree on which schema applies.
		"schema smuggled": `{"schema":"attest.dev/workload-policy/v1","Schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[]}`,
		"unknown schema":  `{"schema":"attest.dev/measurement-policy/v2","pcrs":[0],"references":[]}`,
		"missing schema":  `{"pcrs":[0],"references":[]}`,
		"numeric schema":  `{"schema":1}`,
		"array":           `[{"schema":"attest.dev/measurement-policy/v1"}]`,
		"empty file":      ``,
		"oversized":       `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[]}` + strings.Repeat(" ", 1<<20),
		"workload root":   `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"a","nodes":["n1"],"systemd_unit":"a.service","uid":0}]}`,
		"workload no uid": `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"a","nodes":["n1"],"systemd_unit":"a.service"}]}`,
		"workload ambiguous": `{"schema":"attest.dev/workload-policy/v1","workloads":[{"name":"a","nodes":["n1"],"systemd_unit":"a.service","uid":1000},` +
			`{"name":"b","nodes":["n1"],"systemd_unit":"a.service","uid":1001}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, ctl(t, "policy", "validate", write("bad.json", doc)), 1, "invalid")
		})
	}
	expect(t, ctl(t, "policy", "validate", filepath.Join(dir, "missing.json")), 2, "no such file")
	expect(t, ctl(t, "policy", "validate", dir), 2, "directory")

	wl := write("wl.json", `{"schema":"attest.dev/workload-policy/v1","workloads":[
		{"name":"payments","nodes":["node-a"],"systemd_unit":"payments.service","uid":1001,"ttl":"5m"}]}`)
	expect(t, ctl(t, "policy", "validate", wl), 0, "payments: payments.service uid 1001 on [node-a], ttl 5m0s")
	empty := write("wl-empty.json", `{"schema":"attest.dev/workload-policy/v1","workloads":[]}`)
	expect(t, ctl(t, "policy", "validate", empty), 0, "identifies nothing")
}
