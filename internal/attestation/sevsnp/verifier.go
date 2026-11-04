package sevsnp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	protocolsevsnp "github.com/verirelay/protocol/sevsnp"
	"github.com/verirelay/veriprov/internal/attestation"
)

// guestPolicy is the most a report's guest policy may allow: SMT, but neither
// debugging nor a migration agent.
var guestPolicy = abi.SnpPolicy{SMT: true}

// platformInfo requires ALIAS_CHECK_COMPLETE in a report's PLATFORM_INFO and
// permits every other bit.
var platformInfo = abi.SnpPlatformInfo{SMTEnabled: true, TSMEEnabled: true, TIOEnabled: true, AliasCheckComplete: true}

type VerifierOptions struct {
	Policy Policy
	// AllowedChipIDs holds the CHIP_IDs any deployment allows. A report from
	// another chip is refused before any AMD KDS request.
	AllowedChipIDs   [][abi.ChipIDSize]byte
	Getter           *KDSGetter
	CheckRevocations bool
	TrustedRoots     map[string][]*trust.AMDRootCerts
}

type Verifier struct {
	policy           Policy
	allowedChipIDs   [][abi.ChipIDSize]byte
	getter           *KDSGetter
	checkRevocations bool
	trustedRoots     map[string][]*trust.AMDRootCerts
}

func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if err := options.Policy.Validate(); err != nil {
		return nil, err
	}
	if len(options.AllowedChipIDs) == 0 {
		return nil, errors.New("at least one allowed CHIP_ID is required")
	}
	if options.Getter == nil {
		return nil, errors.New("AMD KDS getter is required")
	}
	return &Verifier{
		policy:           options.Policy,
		allowedChipIDs:   options.AllowedChipIDs,
		getter:           options.Getter,
		checkRevocations: options.CheckRevocations,
		trustedRoots:     options.TrustedRoots,
	}, nil
}

// Verify verifies a raw VCEK-signed Attestation Report against AMD KDS
// endorsements. It requires REPORT_DATA to equal expected, an allowed CHIP_ID,
// a guest policy without debug or a migration agent, VMPL 0, the platform
// baseline and an allowed Launch Measurement.
func (verifier *Verifier) Verify(ctx context.Context, raw []byte, expected [64]byte) (attestation.Report, error) {
	report, err := parseReport(raw)
	if err != nil {
		return attestation.Report{}, err
	}
	if subtle.ConstantTimeCompare(report.GetReportData(), expected[:]) != 1 {
		return attestation.Report{}, fmt.Errorf("%w: REPORT_DATA does not match challenge binding", attestation.ErrReportDataMismatch)
	}
	// The signature does not bind CHIP_ID yet; this check only keeps reports
	// claiming other chips away from AMD KDS.
	chipID := [abi.ChipIDSize]byte(report.GetChipId())
	if !slices.Contains(verifier.allowedChipIDs, chipID) {
		return attestation.Report{}, fmt.Errorf("%w: CHIP_ID is in no deployment's allowed_chip_ids", attestation.ErrPolicyDenied)
	}
	att := &sevsnppb.Attestation{Report: report}
	fetches := &vcekRecorder{getter: verifier.getter}
	options := verify.Options{Getter: fetches, CheckRevocations: verifier.checkRevocations, TrustedRoots: verifier.trustedRoots, Now: time.Now()}
	if err := verify.SnpAttestationContext(ctx, att, &options); err != nil {
		return attestation.Report{}, classifyVerificationError(err)
	}
	fetches.keep()
	vmpl := 0
	if err := validate.SnpAttestation(att, &validate.Options{GuestPolicy: guestPolicy, VMPL: &vmpl}); err != nil {
		return attestation.Report{}, fmt.Errorf("%w: %w", attestation.ErrPolicyDenied, err)
	}
	if err := checkPlatformBaseline(att); err != nil {
		return attestation.Report{}, err
	}
	if err := verifier.policy.Authorize(report); err != nil {
		return attestation.Report{}, err
	}
	return attestation.Report{HostData: [abi.HostDataSize]byte(report.GetHostData()), ChipID: chipID}, nil
}

// checkPlatformBaseline requires the report to come from a CPU model with a
// platform baseline, at or above its minimum REPORTED_TCB and LAUNCH_TCB,
// with ALIAS_CHECK_COMPLETE.
func checkPlatformBaseline(att *sevsnppb.Attestation) error {
	report := att.GetReport()
	baseline, ok := protocolsevsnp.BaselineFor(report.GetCpuid1EaxFms())
	if !ok {
		return fmt.Errorf("%w: platform baseline: no baseline for CPUID %#08x (report version %d)", attestation.ErrPolicyDenied, report.GetCpuid1EaxFms(), report.GetVersion())
	}
	minimum := kds.DecomposeTCBVersion(kds.TCBVersion(baseline.MinimumTCB))
	options := validate.Options{GuestPolicy: guestPolicy, MinimumTCB: minimum, MinimumLaunchTCB: minimum, PlatformInfo: &platformInfo}
	if err := validate.SnpAttestation(att, &options); err != nil {
		return fmt.Errorf("%w: platform baseline for %s (minimum TCB %#016x, %s): %w", attestation.ErrPolicyDenied, baseline.Model, baseline.MinimumTCB, baseline.Bulletins, err)
	}
	return nil
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
