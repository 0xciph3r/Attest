package audit

import (
	"errors"
	"fmt"
	"iter"
)

// Verification failures. Callers should use errors.Is to classify them; the
// concrete error is a *VerifyError carrying the offending sequence number.
var (
	ErrSequence              = errors.New("audit: sequence discontinuity")
	ErrPrevHash              = errors.New("audit: previous-hash mismatch")
	ErrEntryHash             = errors.New("audit: entry hash mismatch")
	ErrCheckpointMismatch    = errors.New("audit: ledger does not match trusted checkpoint")
	ErrTruncated             = errors.New("audit: ledger truncated relative to trusted checkpoint")
	ErrConflictingCheckpoint = errors.New("audit: trusted checkpoints conflict")
	ErrUnanchored            = errors.New("audit: no trusted checkpoint supplied")
)

// VerifyError reports where and why verification failed.
type VerifyError struct {
	Sequence uint64
	Err      error
	Detail   string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%v at sequence %d", e.Err, e.Sequence)
	}
	return fmt.Sprintf("%v at sequence %d: %s", e.Err, e.Sequence, e.Detail)
}

func (e *VerifyError) Unwrap() error { return e.Err }

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Checkpoints are previously exported, signed ledger heads. Each must be
	// signed by a key in Keys and must match the ledger exactly.
	Checkpoints []SignedCheckpoint
	// Keys are the trusted checkpoint verification keys.
	Keys KeyRing
	// AllowUnanchored permits verification with no checkpoints. Such a result
	// only shows internal consistency: anyone with write access to the ledger
	// can produce a consistent rewritten chain.
	AllowUnanchored bool
}

// Report summarizes a successful verification.
type Report struct {
	// Head is the last verified entry.
	Head Head
	// CheckpointsVerified is the number of distinct trusted checkpoints that
	// matched the ledger.
	CheckpointsVerified int
	// AnchoredThrough is the highest checkpointed sequence. Entries after it
	// are internally consistent but not protected by any trusted checkpoint.
	AnchoredThrough uint64
}

// Unanchored returns the number of entries after the last trusted checkpoint.
func (r Report) Unanchored() uint64 { return r.Head.Sequence - r.AnchoredThrough }

// Verify checks that entries form a contiguous, correctly hashed chain from
// genesis and that it agrees with every trusted checkpoint. It fails closed:
// any error from the entry source or any checkpoint problem fails
// verification.
func Verify(entries iter.Seq2[Entry, error], opts VerifyOptions) (Report, error) {
	anchors, maxAnchor, err := trustedAnchors(opts)
	if err != nil {
		return Report{}, err
	}

	var (
		head    Head
		matched int
	)
	for e, err := range entries {
		if err != nil {
			return Report{}, fmt.Errorf("audit: reading entry after sequence %d: %w", head.Sequence, err)
		}
		want := head.Sequence + 1
		if e.Sequence != want {
			return Report{}, &VerifyError{Sequence: want, Err: ErrSequence, Detail: fmt.Sprintf("found sequence %d", e.Sequence)}
		}
		if e.PrevHash != head.Hash {
			return Report{}, &VerifyError{Sequence: e.Sequence, Err: ErrPrevHash}
		}
		if got := e.chainHash(head.Hash); got != e.Hash {
			return Report{}, &VerifyError{Sequence: e.Sequence, Err: ErrEntryHash}
		}
		if anchor, ok := anchors[e.Sequence]; ok {
			if anchor != e.Hash {
				return Report{}, &VerifyError{Sequence: e.Sequence, Err: ErrCheckpointMismatch}
			}
			matched++
		}
		head = Head{Sequence: e.Sequence, Hash: e.Hash}
	}

	if head.Sequence < maxAnchor {
		return Report{}, &VerifyError{
			Sequence: head.Sequence,
			Err:      ErrTruncated,
			Detail:   fmt.Sprintf("ledger ends at %d but a trusted checkpoint covers %d", head.Sequence, maxAnchor),
		}
	}
	return Report{Head: head, CheckpointsVerified: matched, AnchoredThrough: maxAnchor}, nil
}

// trustedAnchors verifies all checkpoint signatures up front and returns the
// required hash at each checkpointed sequence.
func trustedAnchors(opts VerifyOptions) (map[uint64]Hash, uint64, error) {
	if len(opts.Checkpoints) == 0 && !opts.AllowUnanchored {
		return nil, 0, ErrUnanchored
	}
	anchors := make(map[uint64]Hash, len(opts.Checkpoints))
	var maxSeq uint64
	for i := range opts.Checkpoints {
		cp := &opts.Checkpoints[i]
		if err := cp.Verify(opts.Keys); err != nil {
			return nil, 0, err
		}
		if prior, ok := anchors[cp.Sequence]; ok && prior != cp.Hash {
			return nil, 0, &VerifyError{Sequence: cp.Sequence, Err: ErrConflictingCheckpoint}
		}
		anchors[cp.Sequence] = cp.Hash
		maxSeq = max(maxSeq, cp.Sequence)
	}
	return anchors, maxSeq, nil
}
