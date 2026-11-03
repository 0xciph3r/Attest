package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
)

// GenerateKeyFiles creates a new Ed25519 checkpoint signing key. The private
// key is written to privPath with mode 0600 and the public key to pubPath. It
// refuses to overwrite existing files.
func GenerateKeyFiles(privPath, pubPath string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := writeNewFile(privPath, 0o600, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})); err != nil {
		return nil, err
	}
	if err := writeNewFile(pubPath, 0o644, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})); err != nil {
		_ = os.Remove(privPath)
		return nil, err
	}
	return pub, nil
}

// LoadPrivateKey reads a PEM PKCS#8 Ed25519 private key. On Unix it refuses
// keys that are readable or writable by group or others.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY", runtime.GOOS != "windows")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("audit: parse private key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit: private key %s is not Ed25519", path)
	}
	return priv, nil
}

// LoadPublicKey reads a PEM PKIX Ed25519 public key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY", false)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("audit: parse public key %s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("audit: public key %s is not Ed25519", path)
	}
	return pub, nil
}

// maxKeyFileSize bounds a key file; an Ed25519 PEM key is under 200 bytes.
const maxKeyFileSize = 16 << 10

// readPEM returns the contents of the single PEM block of wantType in path.
// The block must be canonically encoded (64-column base64, LF line endings,
// as Attest and openssl write keys) and anything else in the file other
// than surrounding whitespace is rejected, so a file that is not exactly a
// key is not mistaken for one. With private
// set, it checks the permissions of the file it actually opened.
func readPEM(path, wantType string, private bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("audit: %s is not a regular file", path)
	}
	if private && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("audit: private key %s has permissions %v; require 0600 or stricter", path, fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFileSize {
		return nil, fmt.Errorf("audit: %s is larger than %d bytes", path, maxKeyFileSize)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != wantType {
		return nil, fmt.Errorf("audit: %s does not contain a PEM %q block", path, wantType)
	}
	// pem.Decode skips text and malformed blocks around the one it returns.
	// Requiring the canonical encoding leaves nothing else in the file.
	if !bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return nil, fmt.Errorf("audit: %s must contain exactly one canonical PEM %q block and nothing else", path, wantType)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("audit: %s has PEM headers (encrypted keys are not supported)", path)
	}
	return block.Bytes, nil
}

func writeNewFile(path string, perm os.FileMode, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
