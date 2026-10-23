package tpm

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultEventLogPath is where Linux exposes the firmware measured-boot log.
const DefaultEventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

// MaxEventLogSize bounds the event log accepted by agent and verifier.
const MaxEventLogSize = 4 << 20

// ErrEventLogTooLarge is returned when the log exceeds MaxEventLogSize.
var ErrEventLogTooLarge = errors.New("tpm: event log too large")

// ReadEventLog reads a measured-boot event log, refusing oversized input.
func ReadEventLog(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("tpm: open event log: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxEventLogSize+1))
	if err != nil {
		return nil, fmt.Errorf("tpm: read event log: %w", err)
	}
	if len(b) > MaxEventLogSize {
		return nil, ErrEventLogTooLarge
	}
	return b, nil
}
