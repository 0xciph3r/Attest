//go:build linux

package agent

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// When set, the test binary connects to the named socket and exits.
const helperEnv = "ATTEST_AGENT_TEST_DIAL"

func TestMain(m *testing.M) {
	if path := os.Getenv(helperEnv); path != "" {
		c, err := net.Dial("unix", path)
		if err != nil {
			os.Exit(3)
		}
		if os.Getenv(helperEnv+"_SLEEP") != "" {
			_, _ = os.Stdout.Write([]byte("connected\n"))
			select {} // Hold the connection until killed.
		}
		_ = c // Exit with the connection open; the kernel closes it.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func requirePeerPidfd(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrUnsupported) {
		t.Skip("kernel lacks SO_PEERPIDFD")
	}
}

func TestPeerProcessIdentifiesLiveCaller(t *testing.T) {
	l, path := listen(t)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := peerProcess(s)
	requirePeerPidfd(t, err)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseCgroup(self)
	if err != nil {
		t.Skipf("test host is not pure cgroup v2: %v", err)
	}
	if got.PID != int32(os.Getpid()) || got.UID != uint32(os.Geteuid()) || got.Cgroup != want {
		t.Fatalf("identified %+v; want pid %d uid %d cgroup %q", got, os.Getpid(), os.Geteuid(), want)
	}
}

// A caller that exits before the agent identifies it is refused, rather
// than attributed to whatever process later holds its PID.
func TestPeerProcessRefusesExitedCaller(t *testing.T) {
	l, path := listen(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := peerProcess(s)
	requirePeerPidfd(t, err)
	if !errors.Is(err, ErrCallerGone) {
		t.Fatalf("exited caller identified as %+v, %v", got, err)
	}
}

// A caller that exits after its cgroup was read, so that its PID could
// already name another process, is refused.
func TestPeerProcessRefusesCallerExitingDuringLookup(t *testing.T) {
	l, path := listen(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), helperEnv+"="+path, helperEnv+"_SLEEP=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if _, err := out.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	afterCgroupRead = func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	defer func() { afterCgroupRead = func() {} }()
	got, err := peerProcess(s)
	requirePeerPidfd(t, err)
	if !errors.Is(err, ErrCallerGone) {
		t.Fatalf("caller that exited mid-lookup identified as %+v, %v", got, err)
	}
}

// The liveness check that guards against PID reuse reports exit.
func TestPidfdExited(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Skip(err)
	}
	defer unix.Close(pidfd)
	if exited, err := pidfdExited(pidfd); err != nil || exited {
		t.Fatalf("running child reported exited: %v", err)
	}
	if pid, err := pidfdPID(pidfd); err != nil || pid != int32(cmd.Process.Pid) {
		t.Fatalf("pidfd pid %d, %v", pid, err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if exited, err := pidfdExited(pidfd); err != nil || !exited {
		t.Fatalf("killed child not reported exited: %v", err)
	}
	if pid, err := pidfdPID(pidfd); err != nil || pid != -1 {
		t.Fatalf("reaped child pidfd pid %d, %v", pid, err)
	}
}

// identify refuses a caller outside a system service, such as this test.
func TestIdentifyRefusesNonService(t *testing.T) {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := parseCgroup(self); err == nil {
		if _, err := serviceUnit(p); err == nil {
			t.Skipf("test runs inside system service %q", p)
		}
	}
	l, path := listen(t)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := identify(s)
	requirePeerPidfd(t, err)
	if err == nil {
		t.Fatalf("identified %+v", got)
	}
}
