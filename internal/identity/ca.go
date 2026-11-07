package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// Files in a CA directory. CAFile holds the signing key and its
// certificate together so that rotation replaces both in one rename.
const (
	CAFile     = "ca.pem"
	BundleFile = "bundle.pem"
)

const (
	// CALifetime is the validity of a CA certificate.
	CALifetime = 365 * 24 * time.Hour
	// MaxTTL bounds the validity of an issued identity. Revocation relies
	// on short lifetimes, not CRLs.
	MaxTTL = 24 * time.Hour
	// MaxBundle is the number of CAs trusted at once: the current one and,
	// after a rotation, its predecessor.
	MaxBundle = 2
	// clockSkew backdates issued certificates so that a verifier whose
	// clock is slightly behind accepts them.
	clockSkew = time.Minute
	maxFile   = 64 << 10
)

// Errors returned by the CA.
var (
	ErrCAExists  = errors.New("identity: CA already initialised")
	ErrCAInvalid = errors.New("identity: CA files are invalid")
	ErrCAExpired = errors.New("identity: CA certificate is not valid now")
	ErrIssue     = errors.New("identity: refusing to issue")
	ErrUntrusted = errors.New("identity: certificate is not a trusted identity")
)

// Options configure a CA.
type Options struct {
	TrustDomain string
	Now         func() time.Time // default time.Now
	Rand        io.Reader        // serial numbers; default crypto/rand
}

func (o *Options) defaults() error {
	if !ValidTrustDomain(o.TrustDomain) {
		return fmt.Errorf("identity: invalid trust domain %q", o.TrustDomain)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	return nil
}

// CA issues identities in one trust domain. Its signer is the only private
// key the control plane holds; it lives in a file outside the database.
type CA struct {
	opts   Options
	cert   *x509.Certificate
	signer crypto.Signer
	bundle []*x509.Certificate // the current CA first
}

// Cert returns the current CA certificate.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// TrustDomain returns the CA's trust domain.
func (c *CA) TrustDomain() string { return c.opts.TrustDomain }

// Bundle returns the trusted CA certificates, current first.
func (c *CA) Bundle() []*x509.Certificate { return slices.Clone(c.bundle) }

// BundlePEM returns the trust bundle in PEM form.
func (c *CA) BundlePEM() []byte { return encodeCerts(c.bundle) }

// Init creates a CA in dir, which must exist and contain no CA.
func Init(dir string, o Options) (*CA, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	for _, f := range []string{CAFile, BundleFile} {
		if _, err := os.Lstat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s exists", ErrCAExists, f)
		}
	}
	c, keyPEM, err := newCA(o)
	if err != nil {
		return nil, err
	}
	c.bundle = []*x509.Certificate{c.cert}
	if err := writeFile(dir, CAFile, keyPEM, 0o600, false); err != nil {
		return nil, err
	}
	if err := writeFile(dir, BundleFile, c.BundlePEM(), 0o644, false); err != nil {
		return nil, err
	}
	return c, nil
}

// Rotate replaces the CA in dir with a new one. The new trust bundle holds
// the new and the previous CA, so identities issued before the rotation
// stay valid until they expire; a second rotation drops the oldest CA. An
// expired CA can be rotated, which is how a lapsed CA is recovered.
//
// The bundle is replaced before the key: a crash in between leaves the
// previous CA signing under a bundle that already trusts both.
func Rotate(dir string, o Options) (*CA, error) {
	old, err := load(dir, o, false)
	if err != nil {
		return nil, err
	}
	c, keyPEM, err := newCA(old.opts)
	if err != nil {
		return nil, err
	}
	c.bundle = []*x509.Certificate{c.cert, old.cert}
	if err := writeFile(dir, BundleFile, c.BundlePEM(), 0o644, true); err != nil {
		return nil, err
	}
	if err := writeFile(dir, CAFile, keyPEM, 0o600, true); err != nil {
		return nil, err
	}
	return c, nil
}

func newCA(o Options) (*CA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generate CA key: %w", err)
	}
	serial, err := newSerial(o.Rand)
	if err != nil {
		return nil, nil, err
	}
	now := o.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Attest"}, CommonName: "Attest CA " + o.TrustDomain},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: o.TrustDomain}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	out := encodeCerts([]*x509.Certificate{cert})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
	return &CA{opts: o, cert: cert, signer: key}, out, nil
}

// Load reads the CA in dir. It fails closed: the directory and key file
// must not be writable or readable by others, the key must match a valid,
// unexpired, self-signed CA certificate for the trust domain, and the
// bundle must start with that certificate.
func Load(dir string, o Options) (*CA, error) { return load(dir, o, true) }

func load(dir string, o Options, current bool) (*CA, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	b, err := readFile(filepath.Join(dir, CAFile), 0o077)
	if err != nil {
		return nil, err
	}
	certs, key, err := decodePEM(b, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCAInvalid, CAFile, err)
	}
	if len(certs) != 1 || key == nil {
		return nil, fmt.Errorf("%w: %s must hold one certificate and one key", ErrCAInvalid, CAFile)
	}
	cert := certs[0]
	if err := checkCACert(cert, o.TrustDomain); err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%w: key does not match the CA certificate", ErrCAInvalid)
	}
	if now := o.Now(); current && (now.Before(cert.NotBefore) || now.After(cert.NotAfter)) {
		return nil, fmt.Errorf("%w: valid %s to %s", ErrCAExpired, cert.NotBefore, cert.NotAfter)
	}
	b, err = readFile(filepath.Join(dir, BundleFile), 0o022)
	if err != nil {
		return nil, err
	}
	bundle, _, err := decodePEM(b, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCAInvalid, BundleFile, err)
	}
	if len(bundle) == 0 || len(bundle) > MaxBundle || !bundle[0].Equal(cert) {
		return nil, fmt.Errorf("%w: %s must start with the current CA and hold at most %d", ErrCAInvalid, BundleFile, MaxBundle)
	}
	for i, b := range bundle[1:] {
		if err := checkCACert(b, o.TrustDomain); err != nil {
			return nil, err
		}
		if b.Equal(bundle[i]) {
			return nil, fmt.Errorf("%w: duplicate bundle certificate", ErrCAInvalid)
		}
	}
	return &CA{opts: o, cert: cert, signer: key, bundle: bundle}, nil
}

// checkCACert requires a self-signed ECDSA P-256 CA for exactly the trust
// domain that cannot issue intermediates.
func checkCACert(c *x509.Certificate, td string) error {
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !ok || k.Curve != elliptic.P256():
		return fmt.Errorf("%w: CA key must be ECDSA P-256", ErrCAInvalid)
	case !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%w: %q is not a path-length-zero CA", ErrCAInvalid, c.Subject)
	case len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://"+td:
		return fmt.Errorf("%w: CA is not for trust domain %q", ErrCAInvalid, td)
	case len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses) != 0:
		return fmt.Errorf("%w: CA has non-SPIFFE names", ErrCAInvalid)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return fmt.Errorf("%w: CA is not self-signed: %w", ErrCAInvalid, err)
	}
	return nil
}

// IssueRequest asks for an identity certificate for a public key the caller
// has already authenticated and authorized.
type IssueRequest struct {
	ID        ID
	PublicKey crypto.PublicKey
	TTL       time.Duration
	// NotAfter, if set, further bounds the validity, e.g. to the parent
	// identity's.
	NotAfter time.Time
}

// Issued is an issued identity certificate.
type Issued struct {
	Cert   *x509.Certificate
	Serial string // 32 lowercase hex characters
}

// Issue signs an identity certificate. The validity is clamped to the CA's
// own and to req.NotAfter; an identity that would be valid for no time at
// all is refused.
func (c *CA) Issue(req IssueRequest) (*Issued, error) {
	if err := req.ID.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssue, err)
	}
	if req.ID.TrustDomain != c.opts.TrustDomain {
		return nil, fmt.Errorf("%w: %s is outside trust domain %s", ErrIssue, req.ID, c.opts.TrustDomain)
	}
	if req.TTL <= 0 || req.TTL > MaxTTL {
		return nil, fmt.Errorf("%w: TTL %s outside (0, %s]", ErrIssue, req.TTL, MaxTTL)
	}
	if err := checkLeafKey(req.PublicKey); err != nil {
		return nil, err
	}
	now := c.opts.Now()
	notBefore, notAfter := now.Add(-clockSkew), now.Add(req.TTL)
	if notBefore.Before(c.cert.NotBefore) {
		notBefore = c.cert.NotBefore
	}
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("%w: valid until %s", ErrCAExpired, c.cert.NotAfter)
	}
	if !req.NotAfter.IsZero() && notAfter.After(req.NotAfter) {
		notAfter = req.NotAfter
		if !notAfter.After(now) {
			return nil, fmt.Errorf("%w: requested validity ends at %s", ErrIssue, req.NotAfter)
		}
	}
	serial, err := newSerial(c.opts.Rand)
	if err != nil {
		return nil, err
	}
	// Nodes only authenticate to the control plane; the control plane only
	// serves; workloads do both.
	var usage []x509.ExtKeyUsage
	switch req.ID.Kind {
	case KindNode:
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case KindServer:
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	default:
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		URIs:                  []*url.URL{req.ID.URL()},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, req.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("identity: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Issued{Cert: cert, Serial: fmt.Sprintf("%032x", serial)}, nil
}

// checkLeafKey admits only valid ECDSA P-256 public keys, the type the TPM
// node key and libattest generate.
func checkLeafKey(pub crypto.PublicKey) error {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve != elliptic.P256() {
		return fmt.Errorf("%w: public key must be ECDSA P-256", ErrIssue)
	}
	if _, err := k.ECDH(); err != nil {
		return fmt.Errorf("%w: invalid public key: %w", ErrIssue, err)
	}
	return nil
}

// Verify checks that leaf is an identity issued directly by a CA in bundle
// for trust domain td, valid at now and usable for usage, and returns its
// SPIFFE ID.
func Verify(bundle []*x509.Certificate, td string, leaf *x509.Certificate, now time.Time, usage x509.ExtKeyUsage) (ID, error) {
	if leaf == nil || len(bundle) == 0 {
		return ID{}, fmt.Errorf("%w: no certificate or bundle", ErrUntrusted)
	}
	if leaf.IsCA || len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return ID{}, fmt.Errorf("%w: not a SPIFFE leaf certificate", ErrUntrusted)
	}
	roots := x509.NewCertPool()
	for _, c := range bundle {
		roots.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil {
		return ID{}, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	if len(chains) == 0 || len(chains[0]) != 2 {
		return ID{}, fmt.Errorf("%w: not issued directly by a trusted CA", ErrUntrusted)
	}
	id, err := parseURL(leaf.URIs[0])
	if err != nil {
		return ID{}, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	if id.TrustDomain != td {
		return ID{}, fmt.Errorf("%w: %s is outside trust domain %s", ErrUntrusted, id, td)
	}
	return id, nil
}

// newSerial returns a positive 127-bit random serial number.
func newSerial(r io.Reader) (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("identity: serial number: %w", err)
	}
	b[0] &= 0x7f
	s := new(big.Int).SetBytes(b)
	if s.Sign() == 0 {
		return nil, errors.New("identity: serial number: zero")
	}
	return s, nil
}

func encodeCerts(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// decodePEM parses certificates and, if allowed, one PKCS#8 ECDSA P-256
// key. Anything else, including headers or trailing data, is an error.
func decodePEM(b []byte, allowKey bool) ([]*x509.Certificate, *ecdsa.PrivateKey, error) {
	var (
		certs []*x509.Certificate
		key   *ecdsa.PrivateKey
	)
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if len(blk.Headers) != 0 {
			return nil, nil, errors.New("PEM headers are not allowed")
		}
		switch {
		case blk.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, c)
		case blk.Type == "PRIVATE KEY" && allowKey && key == nil:
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok || ec.Curve != elliptic.P256() {
				return nil, nil, errors.New("private key must be ECDSA P-256")
			}
			key = ec
		default:
			return nil, nil, fmt.Errorf("unexpected PEM block %q", blk.Type)
		}
	}
	if len(bytes.TrimSpace(b)) != 0 {
		return nil, nil, errors.New("trailing data")
	}
	return certs, key, nil
}

// checkDir refuses a CA directory that others could write to, since they
// could then replace the trust bundle or the key.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("identity: CA directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrCAInvalid, dir)
	}
	return checkOwner(dir, fi, 0o022)
}

// readFile reads a regular, non-symlinked file owned by this user with no
// permission bits in forbidden.
func readFile(path string, forbidden os.FileMode) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCAInvalid, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrCAInvalid, path)
	}
	if err := checkOwner(path, fi, forbidden); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%w: %s is too large", ErrCAInvalid, path)
	}
	return b, nil
}

func checkOwner(path string, fi os.FileInfo, forbidden os.FileMode) error {
	if fi.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("%w: %s has mode %s", ErrCAInvalid, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrCAInvalid, path, st.Uid)
	}
	return nil
}

// writeFile durably writes name in dir via a temporary file. Without
// replace it fails if name exists.
func writeFile(dir, name string, b []byte, mode os.FileMode, replace bool) (err error) {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("identity: write %s: %w", name, err)
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
		if err != nil {
			err = fmt.Errorf("identity: write %s: %w", name, err)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if replace {
		err = os.Rename(tmp, dst)
	} else {
		err = os.Link(tmp, dst)
	}
	if err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
