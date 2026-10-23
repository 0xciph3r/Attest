// Package policy parses and evaluates Attest policies.
//
// The MVP supports a measurement policy: which PCRs a quote must cover and
// which sets of SHA-256 PCR values are acceptable. Policies are strict JSON
// (unknown fields rejected) and fail closed: a policy with no reference
// measurements admits no machine.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
)

// SchemaMeasurementV1 identifies the measurement policy format.
const SchemaMeasurementV1 = "attest.dev/measurement-policy/v1"

// MaxPolicySize bounds encoded policies.
const MaxPolicySize = 1 << 20

const maxPCR = 23

// Errors returned by this package.
var (
	ErrInvalid                = errors.New("policy: invalid")
	ErrMeasurementNotAllowed  = errors.New("policy: measurements match no reference")
	ErrDevelopmentRootRefused = errors.New("policy: development EK roots are not allowed")
)

// Reference is a named set of acceptable PCR values. A quote satisfies a
// reference when every PCR it lists has exactly the given value.
type Reference struct {
	Name string            `json:"name"`
	PCRs map[string]string `json:"pcrs"`

	values map[uint32][]byte
}

// Measurement is a versioned measurement policy.
type Measurement struct {
	Schema string `json:"schema"`
	// PCRs is the exact SHA-256 PCR selection quotes must cover; every
	// selected PCR is also replayed against the event log.
	PCRs []uint32 `json:"pcrs"`
	// References lists acceptable measurement sets. Empty admits nothing.
	References []Reference `json:"references"`
	// AllowDevelopmentRoots admits nodes whose EK chains to a development
	// root such as swtpm's local CA. Never enable it in production.
	AllowDevelopmentRoots bool `json:"allow_development_roots,omitempty"`

	digest []byte
}

// ParseMeasurement strictly decodes and validates a measurement policy.
func ParseMeasurement(data []byte) (*Measurement, error) {
	if len(data) > MaxPolicySize {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxPolicySize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Measurement
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(&m)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(canonical)
	m.digest = d[:]
	return &m, nil
}

func (m *Measurement) validate() error {
	if m.Schema != SchemaMeasurementV1 {
		return fmt.Errorf("%w: schema must be %q", ErrInvalid, SchemaMeasurementV1)
	}
	if len(m.PCRs) == 0 {
		return fmt.Errorf("%w: pcrs must not be empty", ErrInvalid)
	}
	sel := make(map[uint32]bool, len(m.PCRs))
	for _, p := range m.PCRs {
		if p > maxPCR || sel[p] {
			return fmt.Errorf("%w: bad or duplicate PCR %d", ErrInvalid, p)
		}
		sel[p] = true
	}
	slices.Sort(m.PCRs)
	names := make(map[string]bool, len(m.References))
	for i := range m.References {
		r := &m.References[i]
		if r.Name == "" || names[r.Name] {
			return fmt.Errorf("%w: reference names must be unique and non-empty", ErrInvalid)
		}
		names[r.Name] = true
		if len(r.PCRs) == 0 {
			return fmt.Errorf("%w: reference %q constrains no PCRs", ErrInvalid, r.Name)
		}
		r.values = make(map[uint32][]byte, len(r.PCRs))
		for k, v := range r.PCRs {
			idx, err := strconv.ParseUint(k, 10, 8)
			if err != nil || strconv.FormatUint(idx, 10) != k || !sel[uint32(idx)] {
				return fmt.Errorf("%w: reference %q: PCR %q is not in the selection", ErrInvalid, r.Name, k)
			}
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != sha256.Size {
				return fmt.Errorf("%w: reference %q: PCR %s must be 64 hex characters", ErrInvalid, r.Name, k)
			}
			r.values[uint32(idx)] = b
		}
	}
	return nil
}

// Digest is the SHA-256 of the policy's canonical JSON encoding.
func (m *Measurement) Digest() []byte { return bytes.Clone(m.digest) }

// Evaluate returns the name of the first reference satisfied by pcrs,
// which must be authenticated values covering the policy's selection.
func (m *Measurement) Evaluate(pcrs map[uint32][]byte) (string, error) {
	if !slices.Equal(slices.Sorted(maps.Keys(pcrs)), m.PCRs) {
		return "", fmt.Errorf("%w: PCR set differs from policy selection", ErrMeasurementNotAllowed)
	}
	for _, r := range m.References {
		ok := true
		for idx, want := range r.values {
			if !bytes.Equal(pcrs[idx], want) {
				ok = false
				break
			}
		}
		if ok {
			return r.Name, nil
		}
	}
	return "", ErrMeasurementNotAllowed
}
