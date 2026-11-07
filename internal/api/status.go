// Package api serves attestd's gRPC APIs: NodeService to node agents over
// TLS, and AdminService to operators over a local Unix socket.
//
// Handlers translate requests to the domain services and map their errors
// to gRPC status codes. Denials carry only their stable reason code; the
// detail behind a denial, and any internal error, is recorded server-side
// (in the audit ledger or the log) and never returned to the caller.
package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/0xciph3r/attest/internal/enrollment"
	"github.com/0xciph3r/attest/internal/identity"
	"github.com/0xciph3r/attest/internal/policy"
	"github.com/0xciph3r/attest/internal/store"
	"github.com/0xciph3r/attest/internal/verifier"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of denials.
const ErrorDomain = "attest.dev"

// errInvalid marks a request the API layer itself rejects as malformed.
var errInvalid = errors.New("invalid request")

// toStatus maps a domain error to a gRPC status error. Unrecognised errors
// are logged and returned as an opaque INTERNAL, so that store, filesystem
// or key-handling detail does not reach the caller.
func toStatus(ctx context.Context, log *slog.Logger, method string, err error) error {
	if err == nil {
		return nil
	}
	if r := denialReason(err); r != "" {
		st, derr := status.New(codes.PermissionDenied, "denied: "+r).
			WithDetails(&errdetails.ErrorInfo{Domain: ErrorDomain, Reason: strings.ToUpper(r)})
		if derr != nil {
			return status.Error(codes.PermissionDenied, "denied: "+r)
		}
		return st.Err()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	case errors.Is(err, errInvalid), errors.Is(err, identity.ErrInvalidRequest),
		errors.Is(err, verifier.ErrInvalidRequest), errors.Is(err, enrollment.ErrInvalidNodeID),
		errors.Is(err, enrollment.ErrInvalidChallengeID), errors.Is(err, policy.ErrInvalid):
		// These messages describe only the caller's own input.
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, identity.ErrUntrusted):
		return status.Error(codes.Unauthenticated, "client certificate is not a trusted node identity")
	case errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		return status.Error(codes.AlreadyExists, "conflicts with existing state")
	}
	log.ErrorContext(ctx, "request failed", "method", method, "err", err)
	return status.Error(codes.Internal, "internal error")
}

func denialReason(err error) string {
	if r := verifier.ReasonOf(err); r != "" {
		return string(r)
	}
	return string(identity.ReasonOf(err))
}

// DenialReason extracts the denial code from a status error returned by
// the API, or "" if err is not a denial.
func DenialReason(err error) string {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		return ""
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == ErrorDomain {
			return strings.ToLower(info.GetReason())
		}
	}
	return ""
}
