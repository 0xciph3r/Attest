package api

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ListenUnix listens on a Unix socket at path with the given permission
// bits and, if gid >= 0, group. A stale socket left by a previous run is
// replaced; a live one, or any other file at path, is an error.
//
// The parent directory must not be writable by group or others, so another
// user cannot replace the socket. File permissions are defence in depth:
// callers are authorized by peer UID regardless.
func ListenUnix(path string, mode fs.FileMode, gid int) (net.Listener, error) {
	if mode&^0o660 != 0 {
		return nil, fmt.Errorf("api: socket mode %o grants more than owner and group read/write", mode)
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("api: socket directory: %w", err)
	}
	if !di.IsDir() {
		return nil, fmt.Errorf("api: socket directory %s is not a directory", dir)
	}
	if di.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("api: socket directory %s is writable by group or others", dir)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("api: %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("api: %s is in use by another process", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := setSocketPerm(path, mode, gid); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func setSocketPerm(path string, mode fs.FileMode, gid int) error {
	if gid >= 0 {
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}
