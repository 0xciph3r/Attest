package verifier

import (
	"bytes"
	"crypto/elliptic"
	"maps"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/tpm"
)

// resign replaces the fixture's attest with a and signs it, so the case
// exercises checks after the signature.
func (f *fixture) resign(t *testing.T, a tpm2.TPMSAttest) {
	f.ev.Attest = tpm2.Marshal(a)
	f.ev.Signature = f.ak.sign(t, f.ev.Attest)
}

func ecSig(r, s []byte) []byte {
	return tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash: tpm2.TPMAlgSHA256, SignatureR: tpm2.TPM2BECCParameter{Buffer: r}, SignatureS: tpm2.TPM2BECCParameter{Buffer: s},
		}),
	})
}

func sigRS(t *testing.T, sig []byte) (r, s []byte) {
	t.Helper()
	v, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := v.Signature.ECDSA()
	if err != nil {
		t.Fatal(err)
	}
	return ec.SignatureR.Buffer, ec.SignatureS.Buffer
}

func TestVerifyQuoteRejectsMore(t *testing.T) {
	n := elliptic.P256().Params().N
	z32 := make([]byte, 32)
	tests := []struct {
		name   string
		mutate func(t *testing.T, f *fixture)
		want   Reason
	}{
		{"empty signature", func(_ *testing.T, f *fixture) { f.ev.Signature = nil }, ReasonMalformed},
		{"empty attest", func(_ *testing.T, f *fixture) { f.ev.Attest = nil }, ReasonMalformed},
		{"oversized signature", func(_ *testing.T, f *fixture) { f.ev.Signature = make([]byte, MaxSignatureSize+1) }, ReasonMalformed},
		{"zero r and s", func(_ *testing.T, f *fixture) { f.ev.Signature = ecSig(z32, z32) }, ReasonBadSignature},
		{"empty r and s", func(_ *testing.T, f *fixture) { f.ev.Signature = ecSig(nil, nil) }, ReasonBadSignature},
		{"r equal to curve order", func(t *testing.T, f *fixture) {
			_, s := sigRS(t, f.ev.Signature)
			f.ev.Signature = ecSig(n.FillBytes(make([]byte, 32)), s)
		}, ReasonBadSignature},
		{"r plus curve order", func(t *testing.T, f *fixture) {
			r, s := sigRS(t, f.ev.Signature)
			rn := new(big.Int).Add(new(big.Int).SetBytes(r), n)
			f.ev.Signature = ecSig(rn.Bytes(), s)
		}, ReasonBadSignature},
		{"33-byte r with leading zero", func(t *testing.T, f *fixture) {
			r, s := sigRS(t, f.ev.Signature)
			f.ev.Signature = ecSig(append([]byte{0}, r...), s)
		}, ReasonBadSignature},
		{"ECDAA signature", func(t *testing.T, f *fixture) {
			r, s := sigRS(t, f.ev.Signature)
			f.ev.Signature = tpm2.Marshal(tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgECDAA,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDAA, &tpm2.TPMSSignatureECC{
					Hash: tpm2.TPMAlgSHA256, SignatureR: tpm2.TPM2BECCParameter{Buffer: r}, SignatureS: tpm2.TPM2BECCParameter{Buffer: s},
				}),
			})
		}, ReasonBadSignature},
		{"wrong magic", func(t *testing.T, f *fixture) {
			a := f.ak.attest(f.nonce, f.ev.PCRs)
			a.Magic = 0xdeadbeef
			f.resign(t, a)
		}, ReasonNotQuote},
		{"nonce with extra byte", func(t *testing.T, f *fixture) {
			f.resign(t, f.ak.attest(append(bytes.Clone(f.nonce), 0), f.ev.PCRs))
		}, ReasonNonceMismatch},
		{"nonce prefix", func(t *testing.T, f *fixture) {
			f.resign(t, f.ak.attest(f.nonce[:31], f.ev.PCRs))
		}, ReasonNonceMismatch},
		{"empty quote nonce", func(t *testing.T, f *fixture) {
			f.resign(t, f.ak.attest(nil, f.ev.PCRs))
		}, ReasonNonceMismatch},
		{"quote over more PCRs", func(t *testing.T, f *fixture) {
			pcrs := maps.Clone(f.ev.PCRs)
			pcrs[8] = make([]byte, 32)
			f.resign(t, f.ak.attest(f.nonce, pcrs))
			f.ev.PCRs = pcrs
		}, ReasonPCRSelection},
		{"quote over SHA-1 bank", func(t *testing.T, f *fixture) {
			a := f.ak.attest(f.nonce, f.ev.PCRs)
			q, _ := a.Attested.Quote()
			q.PCRSelect.PCRSelections[0].Hash = tpm2.TPMAlgSHA1
			a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, q)
			f.resign(t, a)
		}, ReasonPCRSelection},
		{"quote over two banks", func(t *testing.T, f *fixture) {
			a := f.ak.attest(f.nonce, f.ev.PCRs)
			q, _ := a.Attested.Quote()
			s := q.PCRSelect.PCRSelections[0]
			s.Hash = tpm2.TPMAlgSHA1
			q.PCRSelect.PCRSelections = append(q.PCRSelect.PCRSelections, s)
			a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, q)
			f.resign(t, a)
		}, ReasonPCRSelection},
		{"quote with empty digest", func(t *testing.T, f *fixture) {
			a := f.ak.attest(f.nonce, f.ev.PCRs)
			q, _ := a.Attested.Quote()
			q.PCRDigest.Buffer = nil
			a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, q)
			f.resign(t, a)
		}, ReasonPCRDigest},
		{"claimed extra PCR", func(_ *testing.T, f *fixture) { f.ev.PCRs[8] = make([]byte, 32) }, ReasonPCRSelection},
		{"claimed nonexistent PCR", func(_ *testing.T, f *fixture) { f.ev.PCRs[24] = make([]byte, 32) }, ReasonPCRSelection},
		{"claimed nil PCR value", func(_ *testing.T, f *fixture) { f.ev.PCRs[7] = nil }, ReasonMalformed},
		{"no claimed PCRs", func(_ *testing.T, f *fixture) { f.ev.PCRs = nil }, ReasonPCRSelection},
		{"oversized event log", func(_ *testing.T, f *fixture) {
			f.ev.EventLog = append(f.ev.EventLog, make([]byte, tpm.MaxEventLogSize)...)
		}, ReasonEventLogInvalid},
		{"event log with trailing garbage", func(_ *testing.T, f *fixture) {
			f.ev.EventLog = append(bytes.Clone(f.ev.EventLog), 0)
		}, ReasonEventLogInvalid},
		{"event log for PCR subset", func(_ *testing.T, f *fixture) {
			b := eventlog.NewBuilder()
			b.Measure(0, eventlog.EvPostCode, []byte("x"))
			f.ev.EventLog = b.Bytes()
		}, ReasonEventLogReplay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.mutate(t, f)
			_, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev)
			if got := ReasonOf(err); got != tt.want {
				t.Fatalf("got reason %q (%v), want %q", got, err, tt.want)
			}
		})
	}
}

// ECDSA signatures are malleable: (r, N-s) verifies too. That is harmless
// here because the signed message carries the single-use nonce, so the
// alternative encoding cannot answer any other challenge.
func TestHighSSignatureIsSameQuote(t *testing.T) {
	f := newFixture(t)
	r, s := sigRS(t, f.ev.Signature)
	ns := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(s))
	f.ev.Signature = ecSig(r, ns.FillBytes(make([]byte, 32)))
	if _, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, f.ev); err != nil {
		t.Fatalf("high-S form rejected: %v", err)
	}
	other := newFixture(t)
	if _, err := VerifyEvidence(f.ak.ak, other.nonce, f.policy, f.ev); ReasonOf(err) != ReasonNonceMismatch {
		t.Fatalf("high-S form answered another nonce: %v", err)
	}
}

func TestVerifyRejectsMissingInputs(t *testing.T) {
	f := newFixture(t)
	bad := map[string]func() error{
		"nil AK": func() error { _, err := VerifyEvidence(nil, f.nonce, f.policy, f.ev); return err },
		"AK without key": func() error {
			_, err := VerifyEvidence(&AK{}, f.nonce, f.policy, f.ev)
			return err
		},
		"nil evidence": func() error { _, err := VerifyEvidence(f.ak.ak, f.nonce, f.policy, nil); return err },
		"empty selection": func() error {
			_, err := VerifyQuote(f.ak.ak, f.nonce, nil, &Evidence{Attest: f.ev.Attest, Signature: f.ev.Signature})
			return err
		},
	}
	for name, call := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			if err := call(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A quote over an empty selection signs SHA-256("") as the PCR digest; it
// must not verify against an empty requirement.
func TestEmptySelectionQuote(t *testing.T) {
	f := newFixture(t)
	a := f.ak.attest(f.nonce, map[uint32][]byte{})
	f.resign(t, a)
	if _, err := VerifyQuote(f.ak.ak, f.nonce, []uint32{}, &Evidence{Attest: f.ev.Attest, Signature: f.ev.Signature}); err == nil {
		t.Fatal("empty-selection quote accepted")
	}
}

// The result must not alias caller-owned evidence.
func TestQuoteInfoDoesNotAliasEvidence(t *testing.T) {
	f := newFixture(t)
	q, err := VerifyQuote(f.ak.ak, f.nonce, bootPCRs, f.ev)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(q.PCRs[0])
	f.ev.PCRs[0][0] ^= 0xff
	if !bytes.Equal(q.PCRs[0], want) {
		t.Fatal("QuoteInfo PCRs alias the evidence")
	}
}

func TestAKKeyMismatchesPublic(t *testing.T) {
	// An AK whose parsed key differs from its signature key must not verify.
	f := newFixture(t)
	other := newSoftAK(t)
	ak := *f.ak.ak
	ak.Key = other.ak.Key
	if _, err := VerifyEvidence(&ak, f.nonce, f.policy, f.ev); ReasonOf(err) != ReasonBadSignature {
		t.Fatalf("got %v", err)
	}
}
