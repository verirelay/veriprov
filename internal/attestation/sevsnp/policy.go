package sevsnp

import (
	"encoding/hex"
	"errors"
	"fmt"

	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"

	"github.com/verirelay/veriprov/internal/attestation"
	"github.com/verirelay/veriprov/internal/strictjson"
)

type Policy struct {
	AllowedMeasurements []string `json:"allowed_measurements"`

	// decodedMeasurements holds AllowedMeasurements decoded by Validate; a
	// Policy that was never validated allows nothing.
	decodedMeasurements [][]byte
}

func DecodePolicy(data []byte) (Policy, error) {
	var policy Policy
	if err := strictjson.Decode(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("decode attestation policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (policy *Policy) Validate() error {
	if len(policy.AllowedMeasurements) == 0 {
		return errors.New("attestation policy allowed_measurements must not be empty")
	}
	measurements := make(map[string]struct{}, len(policy.AllowedMeasurements))
	decoded := make([][]byte, 0, len(policy.AllowedMeasurements))
	for _, value := range policy.AllowedMeasurements {
		if _, duplicate := measurements[value]; duplicate {
			return fmt.Errorf("duplicate measurement %q", value)
		}
		measurement, err := decodeLowerHex(value, 48)
		if err != nil {
			return fmt.Errorf("measurement %q: %w", value, err)
		}
		measurements[value] = struct{}{}
		decoded = append(decoded, measurement)
	}
	policy.decodedMeasurements = decoded
	return nil
}

func (policy Policy) Authorize(report *sevsnppb.Report) error {
	if report == nil {
		return fmt.Errorf("%w: report is missing", attestation.ErrPolicyDenied)
	}
	if !policy.allowsMeasurement(report.GetMeasurement()) {
		return fmt.Errorf("%w: measurement %x is not allowed", attestation.ErrPolicyDenied, report.GetMeasurement())
	}
	return nil
}

func (policy Policy) allowsMeasurement(measurement []byte) bool {
	for _, candidate := range policy.decodedMeasurements {
		if string(measurement) == string(candidate) {
			return true
		}
	}
	return false
}

func decodeLowerHex(value string, expectedBytes int) ([]byte, error) {
	if len(value) != expectedBytes*2 {
		return nil, fmt.Errorf("must be %d lowercase hexadecimal characters", expectedBytes*2)
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil, errors.New("must be lowercase hexadecimal")
		}
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("must be lowercase hexadecimal")
	}
	return decoded, nil
}
