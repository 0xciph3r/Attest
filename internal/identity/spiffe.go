// Package identity issues and verifies short-lived X.509 SPIFFE identities
// for attested nodes and authorized workloads.
package identity

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/0xciph3r/attest/internal/policy"
)

// DefaultTrustDomain is the trust domain used when none is configured.
const DefaultTrustDomain = "attest.local"

// Kind is the kind of subject an identity names.
type Kind string

// Identity kinds.
const (
	KindNode     Kind = "node"
	KindWorkload Kind = "workload"
	// KindServer names the control plane's TLS server identity.
	KindServer Kind = "server"
)

// ErrInvalidID reports a malformed or out-of-scope SPIFFE ID.
var ErrInvalidID = errors.New("identity: invalid SPIFFE ID")

// The SPIFFE trust domain grammar, limited to what a URI host can carry
// without escaping.
var trustDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,253}[a-z0-9])?$`)

// ValidTrustDomain reports whether td is a SPIFFE trust domain name.
func ValidTrustDomain(td string) bool {
	return trustDomainRe.MatchString(td) && !strings.Contains(td, "..")
}

// ID is a parsed Attest SPIFFE ID: spiffe://<trust domain>/<kind>/<name>.
type ID struct {
	TrustDomain string
	Kind        Kind
	Name        string // node ID or workload name
}

// NodeID returns the SPIFFE ID of a node.
func NodeID(td, nodeID string) (ID, error) { return newID(td, KindNode, nodeID) }

// WorkloadID returns the SPIFFE ID of a workload.
func WorkloadID(td, name string) (ID, error) { return newID(td, KindWorkload, name) }

// ServerID returns the SPIFFE ID of a control-plane server.
func ServerID(td, name string) (ID, error) { return newID(td, KindServer, name) }

func newID(td string, k Kind, name string) (ID, error) {
	id := ID{TrustDomain: td, Kind: k, Name: name}
	if err := id.validate(); err != nil {
		return ID{}, err
	}
	return id, nil
}

func (id ID) validate() error {
	if !ValidTrustDomain(id.TrustDomain) {
		return fmt.Errorf("%w: trust domain %q", ErrInvalidID, id.TrustDomain)
	}
	switch id.Kind {
	case KindNode:
		if !policy.ValidNodeID(id.Name) {
			return fmt.Errorf("%w: node ID %q", ErrInvalidID, id.Name)
		}
	case KindWorkload, KindServer:
		if !policy.ValidWorkloadName(id.Name) {
			return fmt.Errorf("%w: workload name %q", ErrInvalidID, id.Name)
		}
	default:
		return fmt.Errorf("%w: kind %q", ErrInvalidID, id.Kind)
	}
	return nil
}

// String returns the SPIFFE ID URI.
func (id ID) String() string { return id.URL().String() }

// URL returns the SPIFFE ID as a URI SAN value.
func (id ID) URL() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: id.TrustDomain, Path: "/" + string(id.Kind) + "/" + id.Name}
}

// ParseID parses an Attest SPIFFE ID. It accepts only the canonical form
// String produces: no user info, port, query, fragment, escaping or path
// segments beyond kind and name.
func ParseID(s string) (ID, error) {
	u, err := url.Parse(s)
	if err != nil {
		return ID{}, fmt.Errorf("%w: %w", ErrInvalidID, err)
	}
	id, err := parseURL(u)
	if err != nil {
		return ID{}, err
	}
	// url.Parse normalizes some components, such as the scheme's case.
	if id.String() != s {
		return ID{}, fmt.Errorf("%w: %q is not canonical", ErrInvalidID, s)
	}
	return id, nil
}

func parseURL(u *url.URL) (ID, error) {
	if u == nil {
		return ID{}, fmt.Errorf("%w: missing", ErrInvalidID)
	}
	if u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Port() != "" {
		return ID{}, fmt.Errorf("%w: %q is not a canonical SPIFFE ID", ErrInvalidID, u)
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 3 || parts[0] != "" {
		return ID{}, fmt.Errorf("%w: %q must have the form spiffe://<domain>/<kind>/<name>", ErrInvalidID, u)
	}
	id := ID{TrustDomain: u.Host, Kind: Kind(parts[1]), Name: parts[2]}
	if err := id.validate(); err != nil {
		return ID{}, err
	}
	if id.String() != u.String() {
		return ID{}, fmt.Errorf("%w: %q is not canonical", ErrInvalidID, u)
	}
	return id, nil
}
