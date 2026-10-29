package attestation

import (
	"context"
	"errors"
)

var (
	ErrMalformedReport       = errors.New("malformed attestation report")
	ErrReportDataMismatch    = errors.New("report data mismatch")
	ErrInvalidEvidence       = errors.New("invalid attestation evidence")
	ErrPolicyDenied          = errors.New("attestation policy denied")
	ErrDependencyUnavailable = errors.New("attestation dependency unavailable")
)

// Verifier verifies a raw Attestation Report whose REPORT_DATA must equal
// reportData, and returns the report's HOST_DATA.
type Verifier interface {
	Verify(ctx context.Context, report []byte, reportData [64]byte) (hostData [32]byte, err error)
}
