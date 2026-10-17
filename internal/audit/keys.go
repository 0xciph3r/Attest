package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("audit: private key %s has permissions %v; require 0600 or stricter", path, fi.Mode().Perm())
		}
	}
	der, err := readPEM(path, "PRIVATE KEY")
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
	der, err := readPEM(path, "PUBLIC KEY")
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

func readPEM(path, wantType string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != wantType {
		return nil, fmt.Errorf("audit: %s does not contain a PEM %q block", path, wantType)
	}
	if len(rest) != 0 {
		if extra, _ := pem.Decode(rest); extra != nil {
			return nil, fmt.Errorf("audit: %s contains more than one PEM block", path)
		}
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
