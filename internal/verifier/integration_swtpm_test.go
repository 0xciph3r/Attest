//go:build swtpm

package verifier_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/eventlog"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
	"github.com/0xciph3r/attest/internal/verifier"
	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

var ctx = context.Background()

// chain wires a real (software) TPM to the control-plane services in process.
type chain struct {
	t      *testing.T
	dev    *swtpmtest.TPM
	st     *store.Store
	enroll *enrollment.Service
	attest *verifier.Service
	ekType tpm.EKType
	prodCA *swtpmtest.CA
	ek, ak *tpm.Key
}

func pemPool(t *testing.T, b []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		p.AddCert(c)
	}
	return p
}

// newChain resets the TPM and configures roots: swtpm's own local CA (which
// certifies the RSA EK) is a development root; a test CA provisioned for the
// ECC EK plays the production manufacturer.
func newChain(t *testing.T, typ tpm.EKType) *chain {
	t.Helper()
	c := &chain{t: t, dev: swtpmtest.Open(t), ekType: typ, prodCA: swtpmtest.NewCA(t, "Production EK CA")}
	ecc, err := tpm.LoadEK(c.dev, tpm.EKECCP256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.Pub(ecc.Public)
	if err != nil {
		t.Fatal(err)
	}
	c.dev.WriteNV(t, tpm.EKCertNVECCP256, c.prodCA.IssueEKCert(t, pub))
	_ = ecc.Flush(c.dev)

	c.loadKeys()
	t.Cleanup(func() { _ = c.ek.Flush(c.dev); _ = c.ak.Flush(c.dev) })

	if c.st, err = store.Open(ctx, filepath.Join(t.TempDir(), "attest.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.st.Close() })
	prod := x509.NewCertPool()
	prod.AddCert(c.prodCA.Cert)
	roots := verifier.EKRoots{
		Production:    prod,
		Development:   pemPool(t, c.dev.ReadFile(t, "ek-root.pem")),
		Intermediates: pemPool(t, c.dev.ReadFile(t, "ek-intermediate.pem")),
	}
	if c.enroll, err = enrollment.New(enrollment.Config{Store: c.st, Roots: roots}); err != nil {
		t.Fatal(err)
	}
	if c.attest, err = verifier.NewService(verifier.ServiceConfig{Store: c.st}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *chain) loadKeys() {
	c.t.Helper()
	var err error
	if c.ek, err = tpm.LoadEK(c.dev, c.ekType); err != nil {
		c.t.Fatal(err)
	}
	if c.ak, err = tpm.LoadAK(c.dev); err != nil {
		c.t.Fatal(err)
	}
}

// reboot resets the TPM (clearing PCRs and transient keys), measures boot
// and reloads the keys, which are deterministic primaries.
func (c *chain) reboot(boot *eventlog.Builder) {
	c.t.Helper()
	if err := c.dev.Reset(); err != nil {
		c.t.Fatal(err)
	}
	c.dev.Boot(c.t, boot)
	c.loadKeys()
}

func (c *chain) applyPolicy(boots ...*eventlog.Builder) {
	c.t.Helper()
	// swtpm's RSA EK chains to its local CA, so it needs development roots.
	allowDev := c.ekType == tpm.EKRSA2048
	if _, err := c.attest.ApplyPolicy(ctx, "operator:alice", verifiertest.PolicyJSON(c.t, allowDev, boots...)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *chain) register(nodeID string) {
	c.t.Helper()
	cert, err := tpm.ReadEKCert(c.dev, c.ekType)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.enroll.Register(ctx, "operator:alice", nodeID, cert); err != nil {
		c.t.Fatalf("Register: %v", err)
	}
}

// enrollNode runs the agent side of enrollment against the real TPM.
func (c *chain) enrollNode(nodeID string) {
	c.t.Helper()
	ch, err := c.enroll.Begin(ctx, nodeID, c.ak.PublicBytes())
	if err != nil {
		c.t.Fatalf("Begin: %v", err)
	}
	secret, err := tpm.ActivateCredential(c.dev, c.ek, c.ak, ch.CredentialBlob, ch.EncryptedSecret)
	if err != nil {
		c.t.Fatalf("ActivateCredential: %v", err)
	}
	if err := c.enroll.Complete(ctx, nodeID, ch.ID, secret); err != nil {
		c.t.Fatalf("Complete: %v", err)
	}
}

// attestNode answers a fresh challenge with a real quote and the given log.
func (c *chain) attestNode(nodeID string, log []byte) (*verifier.Verdict, error) {
	c.t.Helper()
	ch, err := c.attest.Challenge(ctx, nodeID)
	if err != nil {
		c.t.Fatalf("Challenge: %v", err)
	}
	q, err := tpm.MakeQuote(c.dev, c.ak, ch.Nonce, ch.PCRs)
	if err != nil {
		c.t.Fatal(err)
	}
	return c.attest.Verify(ctx, nodeID, ch.ID, ch.Nonce,
		&verifier.Evidence{Attest: q.Attest, Signature: q.Signature, PCRs: q.PCRs, EventLog: log})
}

func wantReason(t *testing.T, err error, want verifier.Reason) {
	t.Helper()
	if got := verifier.ReasonOf(err); got != want {
		t.Fatalf("got reason %q (%v), want %q", got, err, want)
	}
}

func forEachEK(t *testing.T, f func(t *testing.T, c *chain)) {
	for _, typ := range []tpm.EKType{tpm.EKRSA2048, tpm.EKECCP256} {
		t.Run(string(typ), func(t *testing.T) { f(t, newChain(t, typ)) })
	}
}

// The EK public area derived from the certificate, which credentials are
// encrypted to, is the TPM's actual EK.
func TestDerivedEKMatchesTPM(t *testing.T) {
	forEachEK(t, func(t *testing.T, c *chain) {
		cert, err := tpm.ReadEKCert(c.dev, c.ekType)
		if err != nil {
			t.Fatal(err)
		}
		roots := verifier.EKRoots{Production: x509.NewCertPool(),
			Development:   pemPool(t, c.dev.ReadFile(t, "ek-root.pem")),
			Intermediates: pemPool(t, c.dev.ReadFile(t, "ek-intermediate.pem"))}
		roots.Production.AddCert(c.prodCA.Cert)
		ek, err := verifier.VerifyEKCert(cert, roots, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		name, err := tpm2.ObjectName(&ek.Public)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(name.Buffer, c.ek.Name.Buffer) {
			t.Fatal("derived EK name differs from the TPM's EK name")
		}
	})
}

func TestChainOfTrust(t *testing.T) {
	forEachEK(t, func(t *testing.T, c *chain) {
		boot := eventlog.SimulatedBoot("v1")
		c.dev.Boot(t, boot)
		c.applyPolicy(boot)
		c.register("node-1")
		c.enrollNode("node-1")

		v, err := c.attestNode("node-1", boot.Bytes())
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if v.Reference != "boot0" || v.Development != (c.ekType == tpm.EKRSA2048) {
			t.Fatalf("verdict %+v", v)
		}

		t.Run("replayed quote", func(t *testing.T) {
			ch, err := c.attest.Challenge(ctx, "node-1")
			if err != nil {
				t.Fatal(err)
			}
			q, err := tpm.MakeQuote(c.dev, c.ak, ch.Nonce, ch.PCRs)
			if err != nil {
				t.Fatal(err)
			}
			ev := &verifier.Evidence{Attest: q.Attest, Signature: q.Signature, PCRs: q.PCRs, EventLog: boot.Bytes()}
			if _, err := c.attest.Verify(ctx, "node-1", ch.ID, ch.Nonce, ev); err != nil {
				t.Fatal(err)
			}
			_, err = c.attest.Verify(ctx, "node-1", ch.ID, ch.Nonce, ev)
			wantReason(t, err, verifier.ReasonChallengeConsumed)
			// Nor does it answer a new challenge.
			ch2, err := c.attest.Challenge(ctx, "node-1")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.attest.Verify(ctx, "node-1", ch2.ID, ch2.Nonce, ev)
			wantReason(t, err, verifier.ReasonNonceMismatch)
		})

		t.Run("measurement outside the event log", func(t *testing.T) {
			// Something extends PCR 7 without a corresponding log entry.
			c.dev.Extend(t, 7, bytes.Repeat([]byte{0xee}, 32))
			_, err := c.attestNode("node-1", boot.Bytes())
			wantReason(t, err, verifier.ReasonEventLogReplay)
		})

		t.Run("boot not in policy", func(t *testing.T) {
			other := eventlog.SimulatedBoot("v2")
			c.reboot(other)
			_, err := c.attestNode("node-1", other.Bytes())
			wantReason(t, err, verifier.ReasonMeasurement)

			// Rolling out a policy that admits it is an audited operator decision.
			c.applyPolicy(boot, other)
			if _, err := c.attestNode("node-1", other.Bytes()); err != nil {
				t.Fatal(err)
			}
		})

		t.Run("revoked node", func(t *testing.T) {
			if err := c.enroll.Revoke(ctx, "operator:alice", "node-1"); err != nil {
				t.Fatal(err)
			}
			_, err := c.attest.Challenge(ctx, "node-1")
			wantReason(t, err, verifier.ReasonNodeNotEnrolled)
		})
	})
}

// An AK that is not resident in the approved TPM cannot be enrolled.
func TestEnrollmentRequiresResidentAK(t *testing.T) {
	forEachEK(t, func(t *testing.T, c *chain) {
		c.applyPolicy(eventlog.SimulatedBoot("v1"))
		c.register("node-1")

		// A software key with the right template, claimed by the node.
		fake := verifiertest.NewAK(t)
		ch, err := c.enroll.Begin(ctx, "node-1", fake.PublicBytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tpm.ActivateCredential(c.dev, c.ek, c.ak, ch.CredentialBlob, ch.EncryptedSecret); err == nil {
			t.Fatal("TPM released a credential bound to a key it does not hold")
		}
		wantReason(t, c.enroll.Complete(ctx, "node-1", ch.ID, make([]byte, enrollment.SecretSize)),
			verifier.ReasonActivationFailed)

		// The genuine AK still enrolls afterwards.
		c.enrollNode("node-1")
	})
}

// A real AK in a TPM other than the registered one cannot be enrolled: the
// credential is encrypted to the registered EK.
func TestEnrollmentRequiresApprovedTPM(t *testing.T) {
	c := newChain(t, tpm.EKECCP256)
	c.applyPolicy(eventlog.SimulatedBoot("v1"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.enroll.Register(ctx, "operator:alice", "approved", c.prodCA.IssueEKCert(t, &key.PublicKey)); err != nil {
		t.Fatal(err)
	}
	ch, err := c.enroll.Begin(ctx, "approved", c.ak.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.ActivateCredential(c.dev, c.ek, c.ak, ch.CredentialBlob, ch.EncryptedSecret); err == nil {
		t.Fatal("a different TPM activated the credential")
	}
}
