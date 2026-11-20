//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerProcess returns the process at the other end of c. The kernel reports
// the UID and PID captured at connect time and a pidfd for that process.
// The cgroup is read through /proc/<pid>, which is only meaningful while
// the PID still names that process; the pidfd is checked to be alive after
// the read, so a PID reused by another process cannot be mistaken for the
// caller.
func peerProcess(c *net.UnixConn) (*Caller, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		cred       *unix.Ucred
		pidfd      = -1
		cerr, perr error
	)
	if err := raw.Control(func(fd uintptr) {
		if cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); cerr != nil {
			return
		}
		pidfd, perr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return nil, err
	}
	switch {
	case cerr != nil:
		return nil, fmt.Errorf("agent: read peer credentials: %w", cerr)
	case errors.Is(perr, unix.ENOPROTOOPT):
		return nil, ErrUnsupported
	// The kernel cannot make a pidfd for a peer that has exited: ESRCH,
	// or EINVAL once it has been reaped.
	case errors.Is(perr, unix.ESRCH), errors.Is(perr, unix.EINVAL):
		return nil, ErrCallerGone
	case perr != nil:
		return nil, fmt.Errorf("agent: read peer pidfd: %w", perr)
	}
	defer unix.Close(pidfd)

	pid, err := pidfdPID(pidfd)
	if err != nil {
		return nil, err
	}
	// -1: exited. 0: not in this PID namespace, so /proc cannot name it.
	if pid <= 0 || pid != cred.Pid {
		return nil, ErrCallerGone
	}
	b, err := readCgroup(pid)
	if err != nil {
		return nil, err
	}
	afterCgroupRead()
	if exited, err := pidfdExited(pidfd); err != nil || exited {
		return nil, ErrCallerGone
	}
	path, err := parseCgroup(b)
	if err != nil {
		return nil, err
	}
	return &Caller{PID: pid, UID: cred.Uid, Cgroup: path}, nil
}

// afterCgroupRead lets tests end the caller between reading its cgroup and
// checking that it is still alive.
var afterCgroupRead = func() {}

// pidfdPID reads the PID a pidfd refers to, in this PID namespace.
func pidfdPID(pidfd int) (int32, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(pidfd))
	if err != nil {
		return 0, fmt.Errorf("agent: read pidfd info: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 4096))
	for sc.Scan() {
		if v, ok := bytes.CutPrefix(sc.Bytes(), []byte("Pid:")); ok {
			n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 32)
			if err != nil {
				return 0, fmt.Errorf("agent: pidfd info: %w", err)
			}
			return int32(n), nil
		}
	}
	return 0, ErrUnsupported
}

func readCgroup(pid int32) ([]byte, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrCallerGone
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read caller cgroup: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCgroupFile+1))
	if errors.Is(err, unix.ESRCH) {
		return nil, ErrCallerGone
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read caller cgroup: %w", err)
	}
	return b, nil
}

// pidfdExited reports whether the process has exited: a pidfd becomes
// readable when it does.
func pidfdExited(pidfd int) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}} //nolint:gosec // descriptors fit in int32
	for {
		n, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		return n > 0, nil
	}
}
