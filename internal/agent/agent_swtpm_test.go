//go:build swtpm

package agent

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
)

// swtpmNode registers node n2 with the swtpm's ECC EK, boots it with the
// expected measurements and returns a Device over it.
func (e *env) swtpmNode() (*swtpmtest.TPM, *Device, string) {
	t := e.t
	dev := swtpmtest.Open(t)
	ek, err := tpm.LoadEK(dev, tpm.EKECCP256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.Pub(ek.Public)
	if err != nil {
		t.Fatal(err)
	}
	_ = ek.Flush(dev)
	dev.WriteNV(t, tpm.EKCertNVECCP256, e.ekCA.IssueEKCert(t, pub))
	cert, err := tpm.ReadEKCert(dev, tpm.EKECCP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.enr.Register(bg, "operator:alice", "n2", cert); err != nil {
		t.Fatal(err)
	}
	policy := strings.ReplaceAll(workloadPolicy, `["n1"]`, `["n1","n2"]`)
	if _, err := e.ident.ApplyWorkloadPolicy(bg, "operator:alice", []byte(policy)); err != nil {
		t.Fatal(err)
	}

	dev.Boot(t, e.tpm.boot)
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(logPath, e.tpm.boot.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	unique := make([]byte, 32)
	_, _ = rand.Read(unique)
	d, err := OpenDevice(dev, DeviceConfig{EKType: tpm.EKECCP256, NodeKeyUnique: unique, EventLogPath: logPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return dev, d, logPath
}

func TestSwtpmEnrollAttestIssue(t *testing.T) {
	e := newEnv(t)
	_, d, _ := e.swtpmNode()
	a := e.agent(func(c *Config) { c.NodeID, c.TPM = "n2", d })

	if err := a.Attest(bg); err == nil {
		t.Fatal("attested before enrollment")
	}
	if err := a.Enroll(bg); err != nil {
		t.Fatal(err)
	}
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	c := serve(t, a, as(apiCaller))
	id, err := fetch(c, csrFor(t, p256(t)))
	if err != nil {
		t.Fatal(err)
	}
	if id.GetSpiffeId() != "spiffe://attest.local/workload/api" {
		t.Fatalf("spiffe_id = %q", id.GetSpiffeId())
	}
}

func TestSwtpmAttestRejected(t *testing.T) {
	e := newEnv(t)
	dev, d, logPath := e.swtpmNode()
	a := e.agent(func(c *Config) { c.NodeID, c.TPM = "n2", d })
	if err := a.Enroll(bg); err != nil {
		t.Fatal(err)
	}
	if err := a.Attest(bg); err != nil {
		t.Fatal(err)
	}
	held := a.current()

	// A log that does not match the PCRs.
	if err := os.WriteFile(logPath, eventlog.SimulatedBoot("other").Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Attest(bg); api.DenialReason(err) != "event_log_replay_mismatch" {
		t.Fatalf("Attest with a log that does not match the PCRs = %v", err)
	}
	// No log at all.
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := a.Attest(bg); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Attest without an event log = %v", err)
	}
	// A consistent log of an unexpected boot.
	if err := os.WriteFile(logPath, e.tpm.boot.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dev.Extend(t, 7, make([]byte, 32))
	if err := a.Attest(bg); api.DenialReason(err) != "event_log_replay_mismatch" {
		t.Fatalf("Attest after an unmeasured extend = %v", err)
	}
	if a.current() != held {
		t.Fatal("rejected attestations replaced the node identity")
	}
}

func TestSwtpmEnrollRejectsOtherTPM(t *testing.T) {
	e := newEnv(t)
	_, d, _ := e.swtpmNode()
	// The AK of another TPM claims n2, whose EK is in the swtpm: the
	// credential is encrypted to an EK the fake cannot use.
	other := &fakeTPM{t: t, ak: e.tpm.ak, key: e.tpm.key, boot: e.tpm.boot,
		activate: func(blob, secret []byte) ([]byte, error) { return d.ActivateCredential(blob, secret) }}
	a := e.agent(func(c *Config) { c.NodeID, c.TPM = "n2", other })
	if err := a.Enroll(bg); err == nil || !strings.Contains(err.Error(), "activate credential") {
		t.Fatalf("Enroll of an AK that is not in the EK's TPM = %v", err)
	}
}
