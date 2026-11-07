//go:build swtpm

package tpm_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/0xciph3r/attest/internal/tpm"
	"github.com/0xciph3r/attest/internal/tpm/swtpm/swtpmtest"
)

func loadEK(t *testing.T, dev *swtpmtest.TPM, typ tpm.EKType) *tpm.Key {
	t.Helper()
	ek, err := tpm.LoadEK(dev, typ)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ek.Flush(dev) })
	return ek
}

func loadAK(t *testing.T, dev *swtpmtest.TPM) *tpm.Key {
	t.Helper()
	ak, err := tpm.LoadAK(dev)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ak.Flush(dev) })
	return ak
}

func TestEKCertificateMatchesKey(t *testing.T) {
	dev := swtpmtest.Open(t)
	ek := loadEK(t, dev, tpm.EKECCP256)
	pub, err := tpm2.Pub(ek.Public)
	if err != nil {
		t.Fatal(err)
	}
	ca := swtpmtest.NewCA(t, "test EK CA")
	dev.WriteNV(t, tpm.EKCertNVECCP256, ca.IssueEKCert(t, pub))

	for _, typ := range []tpm.EKType{tpm.EKRSA2048, tpm.EKECCP256} {
		t.Run(string(typ), func(t *testing.T) {
			ek := loadEK(t, dev, typ)
			der, err := tpm.ReadEKCert(dev, typ)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := tpm2.Pub(ek.Public)
			if err != nil {
				t.Fatal(err)
			}
			if !cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
				t.Fatal("EK certificate does not certify the EK")
			}
		})
	}
}

func TestUnsupportedEK(t *testing.T) {
	dev := swtpmtest.Open(t)
	if _, err := tpm.LoadEK(dev, "eccp384"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAKIsDeterministic(t *testing.T) {
	dev := swtpmtest.Open(t)
	a := loadAK(t, dev)
	b := loadAK(t, dev)
	if !bytes.Equal(a.Name.Buffer, b.Name.Buffer) {
		t.Fatal("AK name changed between derivations")
	}
}

func TestReadAllPCRs(t *testing.T) {
	dev := swtpmtest.Open(t)
	all := make([]uint32, tpm.MaxPCR+1)
	for i := range all {
		all[i] = uint32(len(all) - 1 - i) // reversed on purpose
	}
	got, err := tpm.ReadPCRs(dev, all)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(all) {
		t.Fatalf("got %d PCRs", len(got))
	}
	if _, err := tpm.ReadPCRs(dev, []uint32{1, 1}); err == nil {
		t.Fatal("duplicate PCRs accepted")
	}
}

func TestQuote(t *testing.T) {
	dev := swtpmtest.Open(t)
	ak := loadAK(t, dev)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	q, err := tpm.MakeQuote(dev, ak, nonce, []uint32{7, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](q.Attest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(attest.ExtraData.Buffer, nonce) {
		t.Fatal("nonce not bound")
	}
	info, err := attest.Attested.Quote()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info.PCRDigest.Buffer, tpm.PCRDigest(q.PCRs)) {
		t.Fatal("PCR digest mismatch")
	}
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](q.Signature)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := sig.Signature.ECDSA()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.Pub(ak.Public)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(q.Attest)
	r, s := new(big.Int).SetBytes(ec.SignatureR.Buffer), new(big.Int).SetBytes(ec.SignatureS.Buffer)
	if !ecdsa.Verify(pub.(*ecdsa.PublicKey), digest[:], r, s) {
		t.Fatal("quote signature does not verify")
	}
}

func TestActivateCredential(t *testing.T) {
	for _, typ := range []tpm.EKType{tpm.EKRSA2048, tpm.EKECCP256} {
		t.Run(string(typ), func(t *testing.T) {
			dev := swtpmtest.Open(t)
			ek := loadEK(t, dev, typ)
			ak := loadAK(t, dev)
			kem, err := tpm2.ImportEncapsulationKey(&ek.Public)
			if err != nil {
				t.Fatal(err)
			}
			secret := []byte("0123456789abcdef0123456789abcdef")
			blob, enc, err := tpm2.CreateCredential(rand.Reader, kem, ak.Name.Buffer, secret)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tpm.ActivateCredential(dev, ek, ak, blob, enc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatal("wrong secret")
			}

			// A credential bound to a different key name must not activate.
			other := sha256.Sum256([]byte("not the AK"))
			blob, enc, err = tpm2.CreateCredential(rand.Reader, kem, append([]byte{0, 0x0b}, other[:]...), secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tpm.ActivateCredential(dev, ek, ak, blob, enc); err == nil {
				t.Fatal("credential for another name was activated")
			}
		})
	}
}

func loadNodeKey(t *testing.T, dev *swtpmtest.TPM, unique []byte) *tpm.Key {
	t.Helper()
	k, err := tpm.LoadNodeKey(dev, unique)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Flush(dev) })
	return k
}

func TestNodeKeyIsSelectedByUnique(t *testing.T) {
	dev := swtpmtest.Open(t)
	u1, u2 := bytes.Repeat([]byte{1}, tpm.NodeKeyUniqueSize), bytes.Repeat([]byte{2}, tpm.NodeKeyUniqueSize)
	a, b, c := loadNodeKey(t, dev, u1), loadNodeKey(t, dev, u1), loadNodeKey(t, dev, u2)
	if !bytes.Equal(a.PublicBytes(), b.PublicBytes()) {
		t.Fatal("same unique value derived different keys")
	}
	if bytes.Equal(a.PublicBytes(), c.PublicBytes()) {
		t.Fatal("different unique values derived the same key")
	}
	if a.Public.ObjectAttributes != tpm.NodeKeyAttributes {
		t.Fatalf("attributes %+v", a.Public.ObjectAttributes)
	}
	if _, err := tpm.LoadNodeKey(dev, u1[:31]); err == nil {
		t.Fatal("short unique value accepted")
	}
}

func TestCertifyNodeKey(t *testing.T) {
	dev := swtpmtest.Open(t)
	ak := loadAK(t, dev)
	key := loadNodeKey(t, dev, make([]byte, tpm.NodeKeyUniqueSize))
	q := tpm.KeyBindingData([]byte("nonce"), key.Name.Buffer)
	c, err := tpm.Certify(dev, ak, key, q)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tpm2.Unmarshal[tpm2.TPMSAttest](c.Attest)
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Attested.Certify()
	if err != nil || a.Type != tpm2.TPMSTAttestCertify || !bytes.Equal(a.ExtraData.Buffer, q) ||
		!bytes.Equal(info.Name.Buffer, key.Name.Buffer) {
		t.Fatalf("certification %+v, %v", a, err)
	}
	// A flushed key cannot be certified.
	if err := key.Flush(dev); err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Certify(dev, ak, key, q); err == nil {
		t.Fatal("certified a flushed key")
	}
}
