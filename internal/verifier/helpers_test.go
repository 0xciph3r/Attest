package verifier

import (
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

type softAK struct {
	*verifiertest.AK
	pub tpm2.TPMTPublic
	ak  *AK
}

func newSoftAK(t *testing.T) *softAK {
	t.Helper()
	a := verifiertest.NewAK(t)
	ak, err := ParseAK(a.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	return &softAK{AK: a, pub: a.Public, ak: ak}
}

func (s *softAK) attest(nonce []byte, pcrs map[uint32][]byte) tpm2.TPMSAttest {
	return s.Attest(nonce, pcrs)
}

func (s *softAK) sign(t *testing.T, msg []byte) []byte { return s.Sign(t, msg) }

var bootPCRs = verifiertest.BootPCRs

// fixture is a valid evidence bundle for a simulated boot.
type fixture struct {
	ak     *softAK
	nonce  []byte
	boot   *eventlog.Builder
	policy *policy.Measurement
	ev     *Evidence
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ak: newSoftAK(t), nonce: make([]byte, 32), boot: eventlog.SimulatedBoot("v1")}
	_, _ = rand.Read(f.nonce)
	f.policy = policyFor(t, f.boot)
	pcrs := f.boot.PCRs(bootPCRs...)
	attest := tpm2.Marshal(f.ak.attest(f.nonce, pcrs))
	f.ev = &Evidence{Attest: attest, Signature: f.ak.sign(t, attest), PCRs: pcrs, EventLog: f.boot.Bytes()}
	return f
}

func policyFor(t *testing.T, boots ...*eventlog.Builder) *policy.Measurement {
	t.Helper()
	m, err := policy.ParseMeasurement(verifiertest.PolicyJSON(t, false, boots...))
	if err != nil {
		t.Fatal(err)
	}
	return m
}
