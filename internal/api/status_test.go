package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier"
)

func TestToStatus(t *testing.T) {
	ctx := context.Background()
	secret := "/var/lib/attest/ca/ca.pem: key material 3f9a"
	for _, tc := range []struct {
		name   string
		err    error
		code   codes.Code
		reason string
	}{
		{"verifier denial", verifier.Reject(verifier.ReasonPCRDigest, "%s", secret), codes.PermissionDenied, "pcr_digest_mismatch"},
		{"identity denial", &identity.Error{Reason: identity.ReasonKeyBinding, Err: errors.New(secret)}, codes.PermissionDenied, "key_binding_mismatch"},
		{"wrapped denial", fmt.Errorf("outer: %w", verifier.Reject(verifier.ReasonNodeUnknown, "x")), codes.PermissionDenied, "node_unknown"},
		{"canceled", fmt.Errorf("%w", context.Canceled), codes.Canceled, ""},
		{"deadline", context.DeadlineExceeded, codes.DeadlineExceeded, ""},
		{"invalid node id", enrollment.ErrInvalidNodeID, codes.InvalidArgument, ""},
		{"invalid challenge id", enrollment.ErrInvalidChallengeID, codes.InvalidArgument, ""},
		{"invalid verifier request", verifier.ErrInvalidRequest, codes.InvalidArgument, ""},
		{"invalid identity request", identity.ErrInvalidRequest, codes.InvalidArgument, ""},
		{"invalid policy", fmt.Errorf("%w: uid 0", policy.ErrInvalid), codes.InvalidArgument, ""},
		{"untrusted client", fmt.Errorf("%w: %s", identity.ErrUntrusted, secret), codes.Unauthenticated, ""},
		{"not found", store.ErrNotFound, codes.NotFound, ""},
		{"conflict", fmt.Errorf("%w: %s", store.ErrConflict, secret), codes.AlreadyExists, ""},
		{"internal", errors.New(secret), codes.Internal, ""},
		{"CA expired", fmt.Errorf("%w: %s", identity.ErrCAExpired, secret), codes.Internal, ""},
	} {
		var logs bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logs, nil))
		err := toStatus(ctx, log, "/m", tc.err)
		st, ok := status.FromError(err)
		if !ok || st.Code() != tc.code {
			t.Errorf("%s: got %v", tc.name, err)
			continue
		}
		if got := DenialReason(err); got != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, got, tc.reason)
		}
		// Denial detail, internal errors and conflicts never reach the
		// caller; only internal errors are logged.
		if strings.Contains(st.Message(), "3f9a") {
			t.Errorf("%s: leaked %q", tc.name, st.Message())
		}
		if logged := strings.Contains(logs.String(), "3f9a"); logged != (tc.code == codes.Internal) {
			t.Errorf("%s: logged=%v: %s", tc.name, logged, logs.String())
		}
	}
	if toStatus(ctx, slog.Default(), "/m", nil) != nil {
		t.Error("nil error mapped to a status")
	}
}

func TestDenialReasonIgnoresForeignDetails(t *testing.T) {
	for name, err := range map[string]error{
		"plain error":           errors.New("pcr_digest_mismatch"),
		"denied without detail": status.Error(codes.PermissionDenied, "denied: pcr_digest_mismatch"),
		"other code":            status.Error(codes.Internal, "x"),
		"nil":                   nil,
	} {
		if r := DenialReason(err); r != "" {
			t.Errorf("%s: %q", name, r)
		}
	}
}
