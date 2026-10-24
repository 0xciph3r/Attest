package verifier

import (
	"errors"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
)

// Result is a successful evidence verification.
type Result struct {
	Quote *QuoteInfo
	// Reference is the policy reference the measurements matched.
	Reference string
	// Events is the number of replayed event log entries.
	Events int
}

// VerifyEvidence authenticates a quote, replays the event log against the
// authenticated PCR values and evaluates the measurement policy.
func VerifyEvidence(ak *AK, nonce []byte, pol *policy.Measurement, ev *Evidence) (*Result, error) {
	if pol == nil {
		return nil, errors.New("verifier: no measurement policy")
	}
	q, err := VerifyQuote(ak, nonce, pol.PCRs, ev)
	if err != nil {
		return nil, err
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
	return &Result{Quote: q, Reference: ref, Events: len(events)}, nil
}
