//go:build darwin

package api

import "golang.org/x/sys/unix"

func peerUID(fd uintptr) (uint32, error) {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
