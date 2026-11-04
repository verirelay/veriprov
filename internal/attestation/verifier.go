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

// Report holds the fields of a verified Attestation Report that pick and
// authorize a deployment.
type Report struct {
	HostData [32]byte
	ChipID   [64]byte
}

// Verifier verifies a raw Attestation Report whose REPORT_DATA must equal
// reportData.
type Verifier interface {
	Verify(ctx context.Context, report []byte, reportData [64]byte) (Report, error)
}
