package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"

	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/secfile"
	"github.com/0xciph3r/attest/internal/strictjson"
	"github.com/0xciph3r/attest/internal/tpm"
)

// maxConfigSize bounds the configuration and bundle files.
const maxConfigSize = 1 << 20

// DefaultTPMDevice is the kernel's resource-managed TPM.
const DefaultTPMDevice = "/dev/tpmrm0"

// Config is the agent's configuration file.
type Config struct {
	// NodeID is the name the operator registered this node under.
	NodeID string `json:"node_id"`
	// TrustDomain is the SPIFFE trust domain of the control plane.
	TrustDomain string `json:"trust_domain"`
	// ControlPlane is attestd's NodeService address, host:port.
	ControlPlane string `json:"control_plane"`
	// Bundle is a PEM file of the control plane's CA bundle. It
	// authenticates attestd until the first attestation returns the
	// current bundle.
	Bundle string `json:"bundle"`
	// WorkloadSocket is the Unix socket the Workload API is served on.
	// Its directory must not be writable by group or others.
	WorkloadSocket string `json:"workload_socket"`
	// WorkloadSocketMode is the socket's permission bits, in octal; at
	// most "0660". Defaults to "0660".
	WorkloadSocketMode string `json:"workload_socket_mode,omitempty"`
	// WorkloadSocketGID, if set, is the socket's group. Workload services
	// join it to reach the socket; the agent still identifies each caller
	// from the kernel.
	WorkloadSocketGID *int `json:"workload_socket_gid,omitempty"`
	// TPM selects the node's TPM.
	TPM TPMConfig `json:"tpm"`

	mode   fs.FileMode
	ekType tpm.EKType
}

// TPMConfig selects the TPM and the measured-boot event log.
type TPMConfig struct {
	// Device is the TPM character device. Defaults to DefaultTPMDevice.
	Device string `json:"device,omitempty"`
	// Swtpm, for development only, is a swtpm data channel, host:port.
	// attestd accepts its EK only under a development EK root.
	Swtpm string `json:"swtpm,omitempty"`
	// EKType is the endorsement key the operator registered: "rsa2048"
	// (default) or "eccp256".
	EKType string `json:"ek_type,omitempty"`
	// EventLog is the measured-boot log. Defaults to
	// tpm.DefaultEventLogPath.
	EventLog string `json:"event_log,omitempty"`
}

// LoadConfig reads and validates the configuration at path. The file must
// be owned by root or the agent's user and not writable by group or
// others.
func LoadConfig(path string) (*Config, error) {
	b, err := secfile.Read(path, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
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
	if !policy.ValidNodeID(c.NodeID) {
		return fmt.Errorf("invalid node_id %q", c.NodeID)
	}
	if !identity.ValidTrustDomain(c.TrustDomain) {
		return fmt.Errorf("invalid trust_domain %q", c.TrustDomain)
	}
	if host, port, err := net.SplitHostPort(c.ControlPlane); err != nil || host == "" || port == "" {
		return fmt.Errorf("control_plane %q must be host:port", c.ControlPlane)
	}
	for name, p := range map[string]string{"bundle": c.Bundle, "workload_socket": c.WorkloadSocket} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	c.mode = 0o660
	if c.WorkloadSocketMode != "" {
		m, err := strconv.ParseUint(c.WorkloadSocketMode, 8, 32)
		if err != nil || m&^0o660 != 0 {
			return fmt.Errorf("workload_socket_mode %q must be octal and at most 0660", c.WorkloadSocketMode)
		}
		c.mode = fs.FileMode(m)
	}
	if c.WorkloadSocketGID != nil && *c.WorkloadSocketGID < 0 {
		return errors.New("workload_socket_gid must not be negative")
	}
	t := &c.TPM
	switch {
	case t.Device != "" && t.Swtpm != "":
		return errors.New("tpm: set device or swtpm, not both")
	case t.Swtpm != "":
		if host, port, err := net.SplitHostPort(t.Swtpm); err != nil || host == "" || port == "" {
			return fmt.Errorf("tpm.swtpm %q must be host:port", t.Swtpm)
		}
	case t.Device == "":
		t.Device = DefaultTPMDevice
	}
	if t.Device != "" && !filepath.IsAbs(t.Device) {
		return errors.New("tpm.device must be an absolute path")
	}
	if t.EventLog == "" {
		t.EventLog = tpm.DefaultEventLogPath
	}
	if !filepath.IsAbs(t.EventLog) {
		return errors.New("tpm.event_log must be an absolute path")
	}
	c.ekType = tpm.EKRSA2048
	if t.EKType != "" {
		c.ekType = tpm.EKType(t.EKType)
	}
	if _, _, err := tpm.EKTemplate(c.ekType); err != nil {
		return fmt.Errorf("tpm.ek_type: %w", err)
	}
	return nil
}

func (c *Config) socketGID() int {
	if c.WorkloadSocketGID == nil {
		return -1
	}
	return *c.WorkloadSocketGID
}

// loadBundle reads the bootstrap trust bundle.
func (c *Config) loadBundle() ([]*x509.Certificate, error) {
	b, err := secfile.Read(c.Bundle, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	certs, err := identity.ParseBundle(b, c.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", c.Bundle, err)
	}
	return certs, nil
}
