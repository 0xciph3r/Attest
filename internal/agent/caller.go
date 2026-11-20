package agent

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/0xciph3r/attest/internal/policy"
)

// Caller is a local process on the workload socket, as identified by the
// kernel. Nothing in it comes from the process itself.
type Caller struct {
	PID int32
	// UID is the effective UID at connect time (SO_PEERCRED).
	UID uint32
	// Unit is the systemd service whose cgroup contains the process.
	Unit string
	// Cgroup is the process's cgroup v2 path, for logs.
	Cgroup string
}

// Caller identification errors. Each refuses the caller; none is retried.
var (
	// ErrUnsupported means the kernel cannot identify callers safely: the
	// agent needs SO_PEERPIDFD (Linux 6.5) and a pure cgroup v2 hierarchy.
	ErrUnsupported = errors.New("agent: kernel cannot identify socket callers (needs Linux >= 6.5 with SO_PEERPIDFD and cgroup v2)")
	// ErrCallerGone means the process exited, or left the agent's PID
	// namespace, before it was identified.
	ErrCallerGone = errors.New("agent: caller exited before it was identified")
	// ErrNotService means the caller is not inside a system service unit.
	ErrNotService = errors.New("agent: caller is not in a systemd system service")
)

// maxCgroupFile bounds /proc/<pid>/cgroup. A cgroup v2 entry is one line
// with a path of at most PATH_MAX.
const maxCgroupFile = 4096 + 16

// parseCgroup returns the cgroup v2 path from the contents of
// /proc/<pid>/cgroup. It refuses hybrid or v1 hierarchies, where the
// unified line does not determine the process's unit by itself.
func parseCgroup(b []byte) (string, error) {
	if len(b) > maxCgroupFile {
		return "", fmt.Errorf("%w: cgroup file too large", ErrUnsupported)
	}
	s, ok := strings.CutSuffix(string(b), "\n")
	if !ok || strings.Contains(s, "\n") {
		return "", fmt.Errorf("%w: not a pure cgroup v2 hierarchy", ErrUnsupported)
	}
	path, ok := strings.CutPrefix(s, "0::")
	if !ok || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%w: not a pure cgroup v2 hierarchy", ErrUnsupported)
	}
	return path, nil
}

// serviceUnit returns the system service that owns a cgroup v2 path:
// /system.slice, then any nested slices, then the .service unit, then any
// sub-cgroups the unit delegates to itself. Everything else is refused,
// notably user managers' units (a user can name a unit anything), scopes
// (containers, sessions), units in slices outside system.slice, and paths
// a cgroup namespace makes relative.
func serviceUnit(path string) (string, error) {
	parts := strings.Split(path, "/")
	// parts[0] is empty: the path is absolute.
	if len(parts) < 3 || parts[0] != "" || parts[1] != "system.slice" {
		return "", fmt.Errorf("%w: cgroup %q", ErrNotService, path)
	}
	for _, p := range parts[2:] {
		switch {
		case p == "" || p == "." || p == "..":
			return "", fmt.Errorf("%w: cgroup %q", ErrNotService, path)
		case strings.HasSuffix(p, ".slice"):
			continue
		case policy.ValidSystemdService(p):
			return p, nil
		default:
			return "", fmt.Errorf("%w: cgroup %q", ErrNotService, path)
		}
	}
	return "", fmt.Errorf("%w: cgroup %q", ErrNotService, path)
}

// identify returns the system service and UID of the process at the other
// end of c.
func identify(c *net.UnixConn) (*Caller, error) {
	caller, err := peerProcess(c)
	if err != nil {
		return nil, err
	}
	if caller.Unit, err = serviceUnit(caller.Cgroup); err != nil {
		return nil, err
	}
	return caller, nil
}
