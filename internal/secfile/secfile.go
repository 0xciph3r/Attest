// Package secfile reads small configuration and trust files that decide
// what a daemon trusts, refusing files another user could have written.
package secfile

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// Read returns the contents of the regular file at path. The file must be
// owned by root or the effective user, must not be writable by group or
// others, and must hold at most max bytes.
func Read(path string, max int64) ([]byte, error) {
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
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by group or others", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s is owned by uid %d, not root or the current user", path, st.Uid)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return b, nil
}
