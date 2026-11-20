package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

func softNodeKey(t *testing.T) (*ecdsa.PrivateKey, *Key) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &Key{Handle: 0x80000001, Name: tpm2.TPM2BName{Buffer: []byte("name")}, Public: nodePublic(t, &priv.PublicKey)}
}

func nodePublic(t *testing.T, pub *ecdsa.PublicKey) tpm2.TPMTPublic {
	t.Helper()
	tmpl, err := NodeKeyTemplate(make([]byte, NodeKeyUniqueSize))
	if err != nil {
		t.Fatal(err)
	}
	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: b[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: b[33:]},
	})
	return tmpl
}

// signResponse scripts TPM2_Sign to return sig.
func signResponse(f *fakeTPM, sig tpm2.TPMTSignature) {
	f.handlers[tpm2.TPMCCSign] = func([]byte) ([]byte, bool) { return tpm2.Marshal(sig), true }
}

func ecdsaSig(hash tpm2.TPMIAlgHash, r, s []byte) tpm2.TPMTSignature {
	return tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA,
		&tpm2.TPMSSignatureECC{Hash: hash, SignatureR: tpm2.TPM2BECCParameter{Buffer: r}, SignatureS: tpm2.TPM2BECCParameter{Buffer: s}})}
}

func softSign(t *testing.T, k *ecdsa.PrivateKey, digest []byte) (r, s []byte) {
	t.Helper()
	ri, si, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		t.Fatal(err)
	}
	return ri.Bytes(), si.Bytes()
}

func TestSignerSigns(t *testing.T) {
	priv, key := softNodeKey(t)
	digest := sha256.Sum256([]byte("handshake"))
	f := newFake()
	r, s := softSign(t, priv, digest[:])
	signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, r, s))
	sg, err := NewSigner(Locked(f), key)
	if err != nil {
		t.Fatal(err)
	}
	if !sg.Public().(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
		t.Fatal("public key differs")
	}
	sig, err := sg.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func TestNewSignerRejects(t *testing.T) {
	_, key := softNodeKey(t)
	restricted := *key
	restricted.Public.ObjectAttributes.Restricted = true
	ak := Key{Public: AKTemplate}
	// A valid P-384 point with node key attributes.
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b384, err := k384.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := *key
	parms, err := key.Public.Parameters.ECCDetail()
	if err != nil {
		t.Fatal(err)
	}
	p384 := *parms
	p384.CurveID = tpm2.TPMECCNistP384
	wrongCurve.Public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &p384)
	wrongCurve.Public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: b384[1:49]}, Y: tpm2.TPM2BECCParameter{Buffer: b384[49:]}})
	offCurve := *key
	offCurve.Public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)}, Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)}})
	rsa := *key
	rsa.Public.Type = tpm2.TPMAlgRSA
	for name, k := range map[string]*Key{
		"nil": nil, "restricted": &restricted, "AK": &ak, "P-384": &wrongCurve, "off curve": &offCurve, "RSA type": &rsa,
	} {
		if _, err := NewSigner(newFake(), k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type hashOpts crypto.Hash

func (h hashOpts) HashFunc() crypto.Hash { return crypto.Hash(h) }

// Digests the key's scheme cannot sign are refused before reaching the TPM.
func TestSignerRejectsDigestsWithoutCallingTPM(t *testing.T) {
	_, key := softNodeKey(t)
	f := newFake()
	sg, err := NewSigner(f, key)
	if err != nil {
		t.Fatal(err)
	}
	d256 := sha256.Sum256(nil)
	for name, c := range map[string]struct {
		digest []byte
		opts   crypto.SignerOpts
	}{
		"nil opts":          {d256[:], nil},
		"SHA-384":           {make([]byte, 48), crypto.SHA384},
		"SHA-256 short":     {d256[:31], crypto.SHA256},
		"SHA-256 long":      {make([]byte, 48), crypto.SHA256},
		"unhashed":          {d256[:], hashOpts(0)},
		"SHA-384 32 bytes":  {d256[:], crypto.SHA384},
		"SHA-1 with 32 len": {d256[:], crypto.SHA1},
	} {
		if _, err := sg.Sign(nil, c.digest, c.opts); !errors.Is(err, ErrSignerHash) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := f.calls[tpm2.TPMCCSign]; n != 0 {
		t.Fatalf("TPM asked to sign %d times", n)
	}
}

// A faulty or malicious TPM cannot make the signer release a signature
// that does not verify under the node key.
func TestSignerRejectsMisbehavingTPM(t *testing.T) {
	priv, key := softNodeKey(t)
	other, _ := softNodeKey(t)
	digest := sha256.Sum256([]byte("handshake"))
	otherDigest := sha256.Sum256([]byte("other"))
	r, s := softSign(t, priv, digest[:])
	fr, fs := softSign(t, other, digest[:])
	or, os := softSign(t, priv, otherDigest[:])
	big := make([]byte, 33)
	big[0] = 1
	for name, script := range map[string]func(f *fakeTPM){
		"TPM error":    func(*fakeTPM) {}, // no handler: TPM_RC_COMMAND_CODE
		"other key":    func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, fr, fs)) },
		"other digest": func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, or, os)) },
		"swapped r s":  func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, s, r)) },
		"zero":         func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, []byte{0}, []byte{0})) },
		"empty":        func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, nil, nil)) },
		"oversized r":  func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA256, big, s)) },
		"SHA-1 hash":   func(f *fakeTPM) { signResponse(f, ecdsaSig(tpm2.TPMAlgSHA1, r, s)) },
		"RSASSA": func(f *fakeTPM) {
			signResponse(f, tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgRSASSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: append(r, s...)}})})
		},
		"truncated": func(f *fakeTPM) {
			f.handlers[tpm2.TPMCCSign] = func([]byte) ([]byte, bool) {
				b := tpm2.Marshal(ecdsaSig(tpm2.TPMAlgSHA256, r, s))
				return b[:len(b)-5], true
			}
		},
	} {
		f := newFake()
		script(f)
		sg, err := NewSigner(f, key)
		if err != nil {
			t.Fatal(err)
		}
		if sig, err := sg.Sign(nil, digest[:], crypto.SHA256); err == nil {
			t.Errorf("%s: released %x", name, sig)
		}
	}
}

// Concurrent signers share one transport without interleaving commands.
func TestLockedSerializes(t *testing.T) {
	var inFlight, peak int
	f := newFake()
	f.handlers[tpm2.TPMCCSign] = func([]byte) ([]byte, bool) { return nil, true }
	tr := &countingTPM{next: f, in: &inFlight, peak: &peak}
	l := Locked(tr)
	done := make(chan struct{})
	for range 16 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 50 {
				_, _ = l.Send(cmdSign)
			}
		}()
	}
	for range 16 {
		<-done
	}
	if peak != 1 {
		t.Fatalf("%d commands in flight at once", peak)
	}
}

var cmdSign = func() []byte {
	return binary.BigEndian.AppendUint32(make([]byte, 6), uint32(tpm2.TPMCCSign))
}()

type countingTPM struct {
	next     *fakeTPM
	in, peak *int
}

func (c *countingTPM) Send(cmd []byte) ([]byte, error) {
	*c.in++
	if *c.in > *c.peak {
		*c.peak = *c.in
	}
	defer func() { *c.in-- }()
	time.Sleep(10 * time.Microsecond)
	return c.next.Send(cmd)
}
