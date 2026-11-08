package verifier

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/0xciph3r/attest/internal/verifier/verifiertest"
)

// boundEvidence is what an honest node submits to bind key to c.
func (e *svcEnv) boundEvidence(ak *verifiertest.AK, key *verifiertest.NodeKey, c *Challenge) *Evidence {
	e.t.Helper()
	pcrs := e.boot.PCRs(c.PCRs...)
	b := ak.BoundEvidence(e.t, c.Nonce, key, pcrs)
	return &Evidence{Attest: b.Attest, Signature: b.Signature, PCRs: pcrs, EventLog: e.boot.Bytes(),
		NodeKey: &KeyEvidence{Public: b.Public, Certify: b.Certify, CertifySignature: b.CertifySignature}}
}

// lastAuditMeta returns the metadata of the newest audit entry.
func (e *svcEnv) lastAuditMeta() (action string, meta map[string]any) {
	e.t.Helper()
	for en, err := range e.st.AuditEntries(bg) {
		if err != nil {
			e.t.Fatal(err)
		}
		action, meta = en.Action, nil
		if err := json.Unmarshal(en.Metadata, &meta); err != nil {
			e.t.Fatal(err)
		}
	}
	return action, meta
}

func TestServiceRecordsKeyBinding(t *testing.T) {
	e := newSvcEnv(t)
	ak := e.node("node-1", false)
	key := verifiertest.NewNodeKey(t)
	want, err := ParseNodeKey(key.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}

	c := e.challenge("node-1")
	v, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, e.boundEvidence(ak, key, c))
	if err != nil {
		t.Fatal(err)
	}
	if v.NodeKey == nil || !bytes.Equal(v.NodeKey.SPKIHash, want.SPKIHash) {
		t.Fatalf("verdict key %+v", v.NodeKey)
	}
	a, err := e.st.LatestAttestation(bg, "node-1")
	if err != nil || !a.Passed || !bytes.Equal(a.KeyBinding, want.SPKIHash) {
		t.Fatalf("recorded %+v, %v", a, err)
	}
	if action, meta := e.lastAuditMeta(); action != ActionAttest || meta["key_binding"] != hex.EncodeToString(want.SPKIHash) {
		t.Fatalf("audit %s %v", action, meta)
	}

	// A plain attestation binds no key, even right after a bound one.
	c = e.challenge("node-1")
	v, err = e.svc.Verify(bg, "node-1", c.ID, c.Nonce, evidence(t, ak, c, e.boot))
	if err != nil || v.NodeKey != nil {
		t.Fatalf("plain: %+v, %v", v, err)
	}
	if a, _ := e.st.LatestAttestation(bg, "node-1"); a.KeyBinding != nil {
		t.Fatalf("plain attestation recorded key binding %x", a.KeyBinding)
	}
	if _, meta := e.lastAuditMeta(); meta["key_binding"] != nil {
		t.Fatalf("plain attestation audited key binding: %v", meta)
	}
	e.verifyAudit()
}

func TestServiceRejectsKeyBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, e *svcEnv, ak *verifiertest.AK, ev *Evidence)
		want   Reason
		// Failures before the quote authenticates are not recorded.
		recorded bool
	}{
		{"key substituted", func(t *testing.T, _ *svcEnv, _ *verifiertest.AK, ev *Evidence) {
			ev.NodeKey.Public = verifiertest.NewNodeKey(t).PublicBytes()
		}, ReasonNonceMismatch, false},
		{"AK as node key", func(_ *testing.T, _ *svcEnv, ak *verifiertest.AK, ev *Evidence) {
			ev.NodeKey.Public = ak.PublicBytes()
		}, ReasonKeyInvalid, false},
		{"certification by another node's AK", func(t *testing.T, _ *svcEnv, _ *verifiertest.AK, ev *Evidence) {
			ev.NodeKey.CertifySignature = verifiertest.NewAK(t).Sign(t, ev.NodeKey.Certify)
		}, ReasonBadSignature, true},
		{"no certification", func(_ *testing.T, _ *svcEnv, _ *verifiertest.AK, ev *Evidence) {
			ev.NodeKey.Certify, ev.NodeKey.CertifySignature = nil, nil
		}, ReasonMalformed, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newSvcEnv(t)
			ak := e.node("node-1", false)
			c := e.challenge("node-1")
			ev := e.boundEvidence(ak, verifiertest.NewNodeKey(t), c)
			tc.mutate(t, e, ak, ev)
			if !tc.recorded {
				e.unchanged(tc.name, func() error {
					_, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
					wantServiceReason(t, err, tc.want)
					return err
				})
				return
			}
			_, err := e.svc.Verify(bg, "node-1", c.ID, c.Nonce, ev)
			wantServiceReason(t, err, tc.want)

			a, err := e.st.LatestAttestation(bg, "node-1")
			if err != nil || a.Passed || a.KeyBinding != nil || a.Reason != string(tc.want) {
				t.Fatalf("recorded %+v, %v", a, err)
			}
			if action, meta := e.lastAuditMeta(); action != ActionAttestDenied || meta["key_binding"] != nil {
				t.Fatalf("audit %s %v", action, meta)
			}
			// The challenge is spent: correct evidence cannot follow.
			_, err = e.svc.Verify(bg, "node-1", c.ID, c.Nonce, e.boundEvidence(ak, verifiertest.NewNodeKey(t), c))
			wantServiceReason(t, err, ReasonChallengeConsumed)
			e.verifyAudit()
		})
	}
}

func TestEvidenceHashCoversNodeKey(t *testing.T) {
	nonce := []byte("nonce")
	plain := &Evidence{Attest: []byte("a"), Signature: []byte("s")}
	base := evidenceHash(nonce, plain)
	bound := func(pub, cert, sig string) *Evidence {
		ev := *plain
		ev.NodeKey = &KeyEvidence{Public: []byte(pub), Certify: []byte(cert), CertifySignature: []byte(sig)}
		return &ev
	}
	hashes := map[string][]byte{"plain": base}
	for name, ev := range map[string]*Evidence{
		"empty key evidence": bound("", "", ""),
		"key":                bound("p", "c", "s"),
		"other public":       bound("q", "c", "s"),
		"other certify":      bound("p", "d", "s"),
		"other signature":    bound("p", "c", "t"),
		"shifted boundary":   bound("pc", "", "s"),
	} {
		h := evidenceHash(nonce, ev)
		for other, oh := range hashes {
			if bytes.Equal(h, oh) {
				t.Errorf("%s hashes like %s", name, other)
			}
		}
		hashes[name] = h
	}
}
