package tpm

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestKeyBindingDataSeparatesFields(t *testing.T) {
	nonce, name := []byte("nonce-0123456789"), []byte("name-0123456789")
	base := KeyBindingData(nonce, name)
	if len(base) != 32 || !bytes.Equal(base, KeyBindingData(nonce, name)) {
		t.Fatalf("not a deterministic SHA-256: %x", base)
	}
	// Moving bytes between fields, swapping fields, or dropping one must
	// change the binding; so must the bare nonce, which is what a plain
	// quote carries.
	for label, got := range map[string][]byte{
		"shifted boundary": KeyBindingData(append(nonce, name[0]), name[1:]),
		"swapped":          KeyBindingData(name, nonce),
		"no name":          KeyBindingData(nonce, nil),
		"no nonce":         KeyBindingData(nil, name),
		"other nonce":      KeyBindingData([]byte("nonce-0123456788"), name),
		"concatenated":     KeyBindingData(append(append([]byte{}, nonce...), name...), nil),
		"bare nonce":       nonce,
	} {
		if bytes.Equal(got, base) {
			t.Errorf("%s: same binding", label)
		}
	}
	if !bytes.Equal(KeyBindingData(nil, nil), KeyBindingData([]byte{}, []byte{})) {
		t.Error("nil and empty fields should encode identically")
	}
}

func TestNodeKeyTemplate(t *testing.T) {
	for _, n := range []int{0, 1, NodeKeyUniqueSize - 1, NodeKeyUniqueSize + 1, 64} {
		if _, err := NodeKeyTemplate(make([]byte, n)); err == nil {
			t.Errorf("unique of %d bytes accepted", n)
		}
	}
	u := bytes.Repeat([]byte{7}, NodeKeyUniqueSize)
	tmpl, err := NodeKeyTemplate(u)
	if err != nil {
		t.Fatal(err)
	}
	u[0] = 8 // the template must not alias the caller's buffer
	p, _ := tmpl.Unique.ECC()
	if p.X.Buffer[0] != 7 {
		t.Fatal("template aliases unique")
	}
	a := tmpl.ObjectAttributes
	if a.Restricted || a.Decrypt || !a.FixedTPM || !a.SensitiveDataOrigin || !a.SignEncrypt {
		t.Fatalf("attributes %+v", a)
	}
	other, _ := NodeKeyTemplate(make([]byte, NodeKeyUniqueSize))
	if bytes.Equal(tpm2.Marshal(tmpl), tpm2.Marshal(other)) {
		t.Fatal("unique value does not select the key")
	}
}

func TestCertifyRequiresKeys(t *testing.T) {
	if _, err := Certify(newFake(), nil, &Key{}, nil); err == nil {
		t.Error("nil AK accepted")
	}
	if _, err := Certify(newFake(), &Key{}, nil, nil); err == nil {
		t.Error("nil key accepted")
	}
}
