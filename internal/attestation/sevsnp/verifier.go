package sevsnp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/go-sev-guest/abi"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/verirelay/veriprov/internal/attestation"
)

type VerifierOptions struct {
	Policy           Policy
	Getter           *KDSGetter
	CheckRevocations bool
	TrustedRoots     map[string][]*trust.AMDRootCerts
}

type Verifier struct {
	policy           Policy
	getter           *KDSGetter
	checkRevocations bool
	trustedRoots     map[string][]*trust.AMDRootCerts
}

func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if err := options.Policy.Validate(); err != nil {
		return nil, err
	}
	if options.Getter == nil {
		return nil, errors.New("AMD KDS getter is required")
	}
	return &Verifier{
		policy:           options.Policy,
		getter:           options.Getter,
		checkRevocations: options.CheckRevocations,
		trustedRoots:     options.TrustedRoots,
	}, nil
}

// Verify verifies a raw VCEK-signed Attestation Report against AMD KDS
// endorsements, requires REPORT_DATA to equal expected, a guest policy without
// debug or a migration agent, VMPL 0 and an allowed Launch Measurement, and
// returns the report's HOST_DATA.
func (verifier *Verifier) Verify(ctx context.Context, raw []byte, expected [64]byte) ([abi.HostDataSize]byte, error) {
	report, err := parseReport(raw)
	if err != nil {
		return [abi.HostDataSize]byte{}, err
	}
	if subtle.ConstantTimeCompare(report.GetReportData(), expected[:]) != 1 {
		return [abi.HostDataSize]byte{}, fmt.Errorf("%w: REPORT_DATA does not match challenge binding", attestation.ErrReportDataMismatch)
	}
	att := &sevsnppb.Attestation{Report: report}
	options := verify.Options{Getter: verifier.getter, CheckRevocations: verifier.checkRevocations, TrustedRoots: verifier.trustedRoots, Now: time.Now()}
	if err := verify.SnpAttestationContext(ctx, att, &options); err != nil {
		return [abi.HostDataSize]byte{}, classifyVerificationError(err)
	}
	vmpl := 0
	if err := validate.SnpAttestation(att, &validate.Options{GuestPolicy: abi.SnpPolicy{SMT: true}, VMPL: &vmpl}); err != nil {
		return [abi.HostDataSize]byte{}, fmt.Errorf("%w: %w", attestation.ErrPolicyDenied, err)
	}
	if err := verifier.policy.Authorize(report); err != nil {
		return [abi.HostDataSize]byte{}, err
	}
	return [abi.HostDataSize]byte(report.GetHostData()), nil
}

func parseReport(raw []byte) (*sevsnppb.Report, error) {
	if len(raw) != abi.ReportSize {
		return nil, fmt.Errorf("%w: report is %d bytes, want %d", attestation.ErrMalformedReport, len(raw), abi.ReportSize)
	}
	if err := abi.ValidateReportFormat(raw); err != nil {
		return nil, fmt.Errorf("%w: %w", attestation.ErrMalformedReport, err)
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", attestation.ErrMalformedReport, err)
	}
	if err := requireVCEKSigner(report); err != nil {
		return nil, err
	}
	return report, nil
}

func requireVCEKSigner(report *sevsnppb.Report) error {
	signer, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return fmt.Errorf("%w: invalid signer info", attestation.ErrMalformedReport)
	}
	if signer.SigningKey == abi.VlekReportSigner {
		return fmt.Errorf("%w: VLEK is not accepted", attestation.ErrPolicyDenied)
	}
	if signer.SigningKey != abi.VcekReportSigner {
		return fmt.Errorf("%w: report is not VCEK-signed", attestation.ErrPolicyDenied)
	}
	return nil
}

// classifyVerificationError reports a failure to obtain AMD certificates or a
// current CRL as ErrDependencyUnavailable, and every other failure as
// ErrInvalidEvidence.
func classifyVerificationError(err error) error {
	if isDependencyError(err) {
		return fmt.Errorf("%w: %w", attestation.ErrDependencyUnavailable, err)
	}
	return fmt.Errorf("%w: %w", attestation.ErrInvalidEvidence, err)
}

func isDependencyError(err error) bool {
	var recreation *trust.AttestationRecreationErr
	var crl verify.CRLUnavailableErr
	var network net.Error
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &recreation) || errors.As(err, &crl) || errors.As(err, &network)
}

var _ attestation.Verifier = (*Verifier)(nil)
