// Package verifier authenticates TPM attestation evidence.
//
// The pure checks in this package (AK and EK validation, quote and event
// log verification, policy evaluation) have no state. Every rejection is a
// *Error carrying a stable Reason code so that callers can audit and test
// failures precisely without parsing messages.
package verifier

import (
	"errors"
	"fmt"
)

// Reason is a stable machine-readable rejection code.
type Reason string

// Rejection reasons.
const (
	ReasonMalformed          Reason = "malformed_evidence"
	ReasonAKInvalid          Reason = "ak_invalid"
	ReasonEKCertInvalid      Reason = "ek_cert_invalid"
	ReasonEKUntrusted        Reason = "ek_untrusted"
	ReasonDevelopmentRoot    Reason = "ek_development_root"
	ReasonBadSignature       Reason = "bad_signature"
	ReasonNotQuote           Reason = "not_a_quote"
	ReasonNonceMismatch      Reason = "nonce_mismatch"
	ReasonPCRSelection       Reason = "pcr_selection_mismatch"
	ReasonPCRDigest          Reason = "pcr_digest_mismatch"
	ReasonEventLogInvalid    Reason = "event_log_invalid"
	ReasonEventLogReplay     Reason = "event_log_replay_mismatch"
	ReasonMeasurement        Reason = "measurement_not_allowed"
	ReasonChallengeUnknown   Reason = "challenge_unknown"
	ReasonChallengeExpired   Reason = "challenge_expired"
	ReasonChallengeConsumed  Reason = "challenge_consumed"
	ReasonChallengeWrongNode Reason = "challenge_wrong_node"
	ReasonNodeNotEnrolled    Reason = "node_not_enrolled"
	ReasonActivationFailed   Reason = "activation_failed"
	ReasonNodeUnknown        Reason = "node_unknown"
	ReasonNodeState          Reason = "node_state_invalid"
	ReasonAKInUse            Reason = "ak_in_use"
	ReasonPolicyMissing      Reason = "policy_missing"
)

// Error is a verification failure.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "verifier: " + string(e.Reason)
	}
	return fmt.Sprintf("verifier: %s: %v", e.Reason, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Reject returns a verification failure with reason r.
func Reject(r Reason, format string, args ...any) *Error { return fail(r, format, args...) }

func fail(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Err: fmt.Errorf(format, args...)}
}

func wrap(r Reason, err error) *Error { return &Error{Reason: r, Err: err} }

// ReasonOf returns the rejection reason of err, or "" if err is not a
// verification failure.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
