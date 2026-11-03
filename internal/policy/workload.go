package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// SchemaWorkloadV1 identifies the workload policy format.
const SchemaWorkloadV1 = "attest.dev/workload-policy/v1"

// Bounds on workload identity lifetimes.
const (
	MinWorkloadTTL     = time.Minute
	MaxWorkloadTTL     = time.Hour
	DefaultWorkloadTTL = 15 * time.Minute
)

// ErrWorkloadNotAllowed is returned when no workload rule matches a caller.
var ErrWorkloadNotAllowed = errors.New("policy: no workload matches the caller")

var (
	nodeIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	workloadNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// systemd unit names: letters, digits and ":-_.\@", at most 255 bytes.
	systemdServiceRe = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]{1,247}\.service$`)
)

// ValidNodeID reports whether id is a well-formed node identifier.
func ValidNodeID(id string) bool { return nodeIDRe.MatchString(id) }

// ValidWorkloadName reports whether name is a well-formed workload name.
func ValidWorkloadName(name string) bool { return workloadNameRe.MatchString(name) }

// Workload authorizes one workload: which nodes it may be identified on and
// the local operating-system boundary that identifies it there. A caller
// matches only if both the systemd service and the UID match.
type Workload struct {
	Name        string   `json:"name"`
	Nodes       []string `json:"nodes"`
	SystemdUnit string   `json:"systemd_unit"`
	UID         *uint32  `json:"uid"`
	// TTL bounds issued identities; default DefaultWorkloadTTL.
	TTL string `json:"ttl,omitempty"`

	ttl time.Duration
}

// Lifetime is the maximum validity of identities issued to the workload.
func (w *Workload) Lifetime() time.Duration { return w.ttl }

// WorkloadPolicy is a versioned set of workload rules. Workloads not listed
// are not identified; an empty policy identifies nothing.
type WorkloadPolicy struct {
	Schema    string     `json:"schema"`
	Workloads []Workload `json:"workloads"`

	digest []byte
}

// Caller is the local boundary the node agent observed for a workload.
type Caller struct {
	NodeID      string
	SystemdUnit string
	UID         uint32
}

// ParseWorkload strictly decodes and validates a workload policy.
func ParseWorkload(data []byte) (*WorkloadPolicy, error) {
	var p WorkloadPolicy
	if err := decodeStrict(data, &p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	var err error
	if p.digest, err = canonicalDigest(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Digest is the SHA-256 of the policy's canonical JSON encoding.
func (p *WorkloadPolicy) Digest() []byte { return slices.Clone(p.digest) }

func (p *WorkloadPolicy) validate() error {
	if p.Schema != SchemaWorkloadV1 {
		return fmt.Errorf("%w: schema must be %q", ErrInvalid, SchemaWorkloadV1)
	}
	names := make(map[string]bool, len(p.Workloads))
	type slot struct{ node, unit string }
	owners := make(map[slot]string)
	for i := range p.Workloads {
		w := &p.Workloads[i]
		if !ValidWorkloadName(w.Name) || names[w.Name] {
			return fmt.Errorf("%w: workload name %q is malformed or duplicated", ErrInvalid, w.Name)
		}
		names[w.Name] = true
		if len(w.Nodes) == 0 {
			return fmt.Errorf("%w: workload %q lists no nodes", ErrInvalid, w.Name)
		}
		if !systemdServiceRe.MatchString(w.SystemdUnit) {
			return fmt.Errorf("%w: workload %q: systemd_unit must name a .service unit", ErrInvalid, w.Name)
		}
		switch {
		case w.UID == nil:
			return fmt.Errorf("%w: workload %q: uid is required", ErrInvalid, w.Name)
		case *w.UID == 0:
			// Root on the node is outside the threat model's protection;
			// a root workload cannot be isolated from the administrator.
			return fmt.Errorf("%w: workload %q: uid 0 cannot be isolated and is not allowed", ErrInvalid, w.Name)
		case *w.UID == 1<<32-1:
			return fmt.Errorf("%w: workload %q: uid %d is the invalid UID", ErrInvalid, w.Name, *w.UID)
		}
		w.ttl = DefaultWorkloadTTL
		if w.TTL != "" {
			d, err := time.ParseDuration(w.TTL)
			if err != nil || d < MinWorkloadTTL || d > MaxWorkloadTTL {
				return fmt.Errorf("%w: workload %q: ttl must be between %s and %s", ErrInvalid, w.Name, MinWorkloadTTL, MaxWorkloadTTL)
			}
			w.ttl = d
		}
		seen := make(map[string]bool, len(w.Nodes))
		for _, n := range w.Nodes {
			if !ValidNodeID(n) || seen[n] {
				return fmt.Errorf("%w: workload %q: node %q is malformed or duplicated", ErrInvalid, w.Name, n)
			}
			seen[n] = true
			// One service on one node maps to at most one workload, so a
			// caller can never be ambiguous.
			if other, dup := owners[slot{n, w.SystemdUnit}]; dup {
				return fmt.Errorf("%w: %s on node %q is claimed by workloads %q and %q", ErrInvalid, w.SystemdUnit, n, other, w.Name)
			}
			owners[slot{n, w.SystemdUnit}] = w.Name
		}
	}
	return nil
}

// Match returns the workload the caller is authorized as. Node, service and
// UID must all match one rule.
func (p *WorkloadPolicy) Match(c Caller) (*Workload, error) {
	for i := range p.Workloads {
		w := &p.Workloads[i]
		if w.SystemdUnit == c.SystemdUnit && *w.UID == c.UID && slices.Contains(w.Nodes, c.NodeID) {
			return w, nil
		}
	}
	return nil, ErrWorkloadNotAllowed
}
