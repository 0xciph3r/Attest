package verifier

import (
	"errors"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/tpm"
)

// Result is a successful evidence verification.
type Result struct {
	Quote *QuoteInfo
	// Reference is the policy reference the measurements matched.
	Reference string
	// Events is the number of replayed event log entries.
	Events int
	// NodeKey is the key bound to the attestation, if one was requested.
	NodeKey *NodeKey
}

// VerifyEvidence authenticates a quote, replays the event log against the
// authenticated PCR values and evaluates the measurement policy. If the
// evidence carries a node key, the quote and the key's certification must
// both be bound to tpm.KeyBindingData(nonce, key name), so the key is only
// accepted together with the boot state the quote proves.
func VerifyEvidence(ak *AK, nonce []byte, pol *policy.Measurement, ev *Evidence) (*Result, error) {
	if pol == nil {
		return nil, errors.New("verifier: no measurement policy")
	}
	if ev == nil {
		return nil, fail(ReasonMalformed, "no evidence")
	}
	key, qualifying, err := qualifyingData(nonce, ev)
	if err != nil {
		return nil, err
	}
	q, err := VerifyQuote(ak, qualifying, pol.PCRs, ev)
	if err != nil {
		return nil, err
	}
	if key != nil {
		if err := VerifyCertify(ak, key, qualifying, q, ev.NodeKey); err != nil {
			return nil, err
		}
	}
	events, err := eventlog.ParseAndReplay(ev.EventLog, q.PCRs)
	switch {
	case errors.Is(err, eventlog.ErrReplay):
		return nil, wrap(ReasonEventLogReplay, err)
	case err != nil:
		return nil, wrap(ReasonEventLogInvalid, err)
	}
	ref, err := pol.Evaluate(q.PCRs)
	if err != nil {
		return nil, wrap(ReasonMeasurement, err)
	}
	return &Result{Quote: q, Reference: ref, Events: len(events), NodeKey: key}, nil
}

// qualifyingData is what the quote must be bound to: the nonce, or, when
// the evidence binds a node key, the nonce and the key's name.
func qualifyingData(nonce []byte, ev *Evidence) (*NodeKey, []byte, error) {
	if ev.NodeKey == nil {
		return nil, nonce, nil
	}
	key, err := ParseNodeKey(ev.NodeKey.Public)
	if err != nil {
		return nil, nil, err
	}
	if len(nonce) == 0 {
		return nil, nil, fail(ReasonNonceMismatch, "no nonce")
	}
	return key, tpm.KeyBindingData(nonce, key.Name), nil
}

// AuthenticateEvidence checks only that ev holds a quote signed by ak in
// answer to nonce, so that a failure found later is attributable to the
// node's TPM rather than to whoever sent the request.
func AuthenticateEvidence(ak *AK, nonce []byte, ev *Evidence) error {
	if ak == nil || ak.Key == nil {
		return errors.New("verifier: no attestation key")
	}
	if ev == nil {
		return fail(ReasonMalformed, "no evidence")
	}
	_, qualifying, err := qualifyingData(nonce, ev)
	if err != nil {
		return err
	}
	_, err = authenticQuote(ak, qualifying, ev)
	return err
}
