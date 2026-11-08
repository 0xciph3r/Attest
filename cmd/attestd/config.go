package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/0xciph3r/attest/internal/api"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/strictjson"
	"github.com/0xciph3r/attest/internal/verifier"
)

// maxConfigSize bounds the configuration file and each EK root file.
const maxConfigSize = 1 << 20

// Config is attestd's configuration file.
type Config struct {
	// TrustDomain is the SPIFFE trust domain identities are issued in.
	TrustDomain string `json:"trust_domain"`
	// StateDir holds the database and, under ca/, the CA. It must be owned
	// by attestd's user and not writable by anyone else.
	StateDir string `json:"state_dir"`
	// NodeListen is the TCP address NodeService is served on.
	NodeListen string `json:"node_listen"`
	// AdminSocket is the Unix socket AdminService is served on.
	AdminSocket string `json:"admin_socket"`
	// AdminSocketMode is the socket's permission bits, in octal; at most
	// "0660". Defaults to "0600".
	AdminSocketMode string `json:"admin_socket_mode,omitempty"`
	// AdminSocketGID, if set, is the socket's group.
	AdminSocketGID *int `json:"admin_socket_gid,omitempty"`
	// Operators are the local users allowed on the admin socket.
	Operators []OperatorConfig `json:"operators"`
	// EKRoots are PEM files of trusted EK certificate issuers.
	EKRoots EKRootsConfig `json:"ek_roots"`
	// ServerCertTTL is the validity of attestd's TLS certificate.
	// Defaults to api.DefaultServerCertTTL.
	ServerCertTTL string `json:"server_cert_ttl,omitempty"`

	adminMode     fs.FileMode
	serverCertTTL time.Duration
}

// OperatorConfig maps a local UID to an operator.
type OperatorConfig struct {
	UID  *uint32  `json:"uid"`
	Name string   `json:"name"`
	Role api.Role `json:"role"`
}

// EKRootsConfig lists EK root and intermediate certificate files.
type EKRootsConfig struct {
	Production    []string `json:"production"`
	Development   []string `json:"development,omitempty"`
	Intermediates []string `json:"intermediates,omitempty"`
}

// DBPath returns the database path.
func (c *Config) DBPath() string { return filepath.Join(c.StateDir, "attest.db") }

// CADir returns the CA directory.
func (c *Config) CADir() string { return filepath.Join(c.StateDir, "ca") }

// LoadConfig reads and validates the configuration at path. The file must
// not be writable by group or others.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("config: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("config: %s is writable by group or others", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigSize {
		return nil, fmt.Errorf("config: %s exceeds %d bytes", path, maxConfigSize)
	}
	var c Config
	if err := strictjson.Decode(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if !identity.ValidTrustDomain(c.TrustDomain) {
		return fmt.Errorf("invalid trust_domain %q", c.TrustDomain)
	}
	for name, p := range map[string]string{"state_dir": c.StateDir, "admin_socket": c.AdminSocket} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if _, _, err := net.SplitHostPort(c.NodeListen); err != nil {
		return fmt.Errorf("node_listen: %w", err)
	}
	c.adminMode = 0o600
	if c.AdminSocketMode != "" {
		m, err := strconv.ParseUint(c.AdminSocketMode, 8, 32)
		if err != nil || m&^0o660 != 0 {
			return fmt.Errorf("admin_socket_mode %q must be octal and at most 0660", c.AdminSocketMode)
		}
		c.adminMode = fs.FileMode(m)
	}
	if c.AdminSocketGID != nil && *c.AdminSocketGID < 0 {
		return errors.New("admin_socket_gid must not be negative")
	}
	if len(c.Operators) == 0 {
		return errors.New("at least one operator is required")
	}
	seen := map[uint32]bool{}
	for i, op := range c.Operators {
		if op.UID == nil {
			return fmt.Errorf("operators[%d]: uid is required", i)
		}
		if seen[*op.UID] {
			return fmt.Errorf("operators[%d]: uid %d is listed twice", i, *op.UID)
		}
		seen[*op.UID] = true
	}
	if len(c.EKRoots.Production)+len(c.EKRoots.Development) == 0 {
		return errors.New("ek_roots: at least one production or development root is required")
	}
	c.serverCertTTL = api.DefaultServerCertTTL
	if c.ServerCertTTL != "" {
		d, err := time.ParseDuration(c.ServerCertTTL)
		if err != nil || d <= 0 || d > identity.MaxTTL {
			return fmt.Errorf("server_cert_ttl %q must be a duration in (0, %s]", c.ServerCertTTL, identity.MaxTTL)
		}
		c.serverCertTTL = d
	}
	return nil
}

// operators returns the operator allowlist for the admin server.
func (c *Config) operators() map[uint32]api.Operator {
	ops := make(map[uint32]api.Operator, len(c.Operators))
	for _, op := range c.Operators {
		ops[*op.UID] = api.Operator{Name: op.Name, Role: op.Role}
	}
	return ops
}

func (c *Config) socketGID() int {
	if c.AdminSocketGID == nil {
		return -1
	}
	return *c.AdminSocketGID
}

// ekRoots loads the configured EK certificate pools.
func (c *Config) ekRoots() (verifier.EKRoots, error) {
	var (
		r   verifier.EKRoots
		err error
	)
	if r.Production, err = loadPool(c.EKRoots.Production); err != nil {
		return r, err
	}
	if r.Development, err = loadPool(c.EKRoots.Development); err != nil {
		return r, err
	}
	r.Intermediates, err = loadPool(c.EKRoots.Intermediates)
	return r, err
}

// loadPool reads PEM certificates from files, or returns nil for none.
// Every file must hold at least one certificate and nothing else.
func loadPool(files []string) (*x509.CertPool, error) {
	if len(files) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, name := range files {
		b, err := readSmall(name)
		if err != nil {
			return nil, fmt.Errorf("ek_roots: %w", err)
		}
		n := 0
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("ek_roots: %s contains a %s block", name, blk.Type)
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("ek_roots: %s: %w", name, err)
			}
			pool.AddCert(cert)
			n++
		}
		if n == 0 || len(bytes.TrimSpace(b)) != 0 {
			return nil, fmt.Errorf("ek_roots: %s is not a PEM certificate file", name)
		}
	}
	return pool, nil
}

func readSmall(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, maxConfigSize)
	}
	return b, nil
}
