package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var (
	v0 = strings.Repeat("00", 32)
	v1 = strings.Repeat("11", 32)
	v2 = strings.Repeat("22", 32)
)

func pcrs(vals map[uint32]string) map[uint32][]byte {
	out := map[uint32][]byte{}
	for k, v := range vals {
		b, _ := hex.DecodeString(v)
		out[k] = b
	}
	return out
}

const good = `{
  "schema": "attest.dev/measurement-policy/v1",
  "pcrs": [7, 0],
  "references": [
    {"name": "fw-a", "pcrs": {"0": "` + "%A" + `", "7": "` + "%B" + `"}},
    {"name": "fw-b", "pcrs": {"0": "` + "%C" + `"}}
  ]
}`

func goodPolicy() string {
	return strings.NewReplacer("%A", v1, "%B", v2, "%C", v2).Replace(good)
}

func TestEvaluate(t *testing.T) {
	m, err := ParseMeasurement([]byte(goodPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if m.AllowDevelopmentRoots {
		t.Fatal("development roots allowed by default")
	}
	tests := []struct {
		name string
		pcrs map[uint32][]byte
		want string
		err  error
	}{
		{"matches first", pcrs(map[uint32]string{0: v1, 7: v2}), "fw-a", nil},
		{"matches second", pcrs(map[uint32]string{0: v2, 7: v0}), "fw-b", nil},
		{"no match", pcrs(map[uint32]string{0: v1, 7: v1}), "", ErrMeasurementNotAllowed},
		{"missing PCR", pcrs(map[uint32]string{0: v1}), "", ErrMeasurementNotAllowed},
		{"extra PCR", pcrs(map[uint32]string{0: v1, 7: v2, 8: v0}), "", ErrMeasurementNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.Evaluate(tt.pcrs)
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestEmptyReferencesAdmitNothing(t *testing.T) {
	m, err := ParseMeasurement([]byte(`{"schema":"attest.dev/measurement-policy/v1","pcrs":[0],"references":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Evaluate(pcrs(map[uint32]string{0: v0})); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Fatalf("got %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	base := `{"schema":"attest.dev/measurement-policy/v1","pcrs":[0,7],"references":[{"name":"a","pcrs":{"0":"` + v1 + `"}}]}`
	if _, err := ParseMeasurement([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown field":      strings.Replace(base, `"pcrs":[0,7]`, `"pcrs":[0,7],"extra":1`, 1),
		"wrong schema":       strings.Replace(base, "v1", "v2", 1),
		"no pcrs":            strings.Replace(base, `[0,7]`, `[]`, 1),
		"duplicate pcr":      strings.Replace(base, `[0,7]`, `[0,0]`, 1),
		"pcr out of range":   strings.Replace(base, `[0,7]`, `[0,24]`, 1),
		"ref outside sel":    strings.Replace(base, `"0":"`, `"8":"`, 1),
		"ref non-canonical":  strings.Replace(base, `"0":"`, `"00":"`, 1),
		"short digest":       strings.Replace(base, v1, "11", 1),
		"bad hex":            strings.Replace(base, v1, strings.Repeat("zz", 32), 1),
		"empty ref":          strings.Replace(base, `{"0":"`+v1+`"}`, `{}`, 1),
		"unnamed ref":        strings.Replace(base, `"name":"a"`, `"name":""`, 1),
		"trailing data":      base + `{}`,
		"duplicate ref name": strings.Replace(base, `}]}`, `},{"name":"a","pcrs":{"7":"`+v1+`"}}]}`, 1),
		"oversized":          base + strings.Repeat(" ", MaxPolicySize),
	} {
		if _, err := ParseMeasurement([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestDigestIsCanonical(t *testing.T) {
	a, err := ParseMeasurement([]byte(goodPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseMeasurement([]byte(strings.ReplaceAll(goodPolicy(), "\n", "")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Digest(), b.Digest()) {
		t.Fatal("whitespace changed the digest")
	}
	c, _ := ParseMeasurement([]byte(strings.Replace(goodPolicy(), `"fw-b"`, `"fw-c"`, 1)))
	if bytes.Equal(a.Digest(), c.Digest()) {
		t.Fatal("content change did not change the digest")
	}
}
