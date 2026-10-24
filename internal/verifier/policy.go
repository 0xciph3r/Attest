package verifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
)

// CurrentPolicy loads the active measurement policy within tx. A missing
// policy is a ReasonPolicyMissing rejection; a stored policy that no longer
// parses or whose digest differs is an internal error, so the caller fails
// closed without recording a verdict.
func CurrentPolicy(tx *store.Tx) (*policy.Measurement, int64, error) {
	p, err := tx.CurrentPolicy(store.PolicyMeasurement)
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, fail(ReasonPolicyMissing, "no measurement policy has been applied")
	}
	if err != nil {
		return nil, 0, err
	}
	m, err := policy.ParseMeasurement(p.Document)
	if err != nil {
		return nil, 0, fmt.Errorf("verifier: stored policy v%d: %w", p.Version, err)
	}
	if !bytes.Equal(m.Digest(), p.Digest) {
		return nil, 0, fmt.Errorf("verifier: stored policy v%d digest mismatch", p.Version)
	}
	return m, p.Version, nil
}

// AdmitRoot refuses a node whose EK chains only to a development root unless
// the policy explicitly allows development roots.
func AdmitRoot(development bool, m *policy.Measurement) error {
	if development && (m == nil || !m.AllowDevelopmentRoots) {
		return wrap(ReasonDevelopmentRoot, policy.ErrDevelopmentRootRefused)
	}
	return nil
}
