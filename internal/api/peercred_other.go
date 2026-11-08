//go:build !linux && !darwin

package api

import "errors"

func peerUID(uintptr) (uint32, error) {
	return 0, errors.New("api: peer credentials are not supported on this platform")
}
