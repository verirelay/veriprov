package sevsnp

import (
	"errors"
	"strings"
	"testing"

	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"

	"github.com/verirelay/veriprov/internal/attestation"
)

const testMeasurement = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"

func testPolicy() Policy {
	return Policy{AllowedMeasurements: []string{testMeasurement}}
}

func testReport(t *testing.T) *sevsnppb.Report {
	t.Helper()
	measurement, err := decodeLowerHex(testMeasurement, 48)
	if err != nil {
		t.Fatal(err)
	}
	return &sevsnppb.Report{Measurement: measurement}
}

func TestPolicyValidateAndAuthorize(t *testing.T) {
	policy := testPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := policy.Authorize(testReport(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodePolicyAcceptsMeasurementStringsOnly(t *testing.T) {
	input := `{"allowed_measurements":["` + testMeasurement + `"]}`
	if _, err := DecodePolicy([]byte(input)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodePolicyRejectsLegacyAndUnexpectedFields(t *testing.T) {
	cases := []string{
		`{"version":"veriprov-attestation-policy-v1","allowed_measurements":["` + testMeasurement + `"]}`,
		`{"tee_type":"sev-snp","allowed_measurements":["` + testMeasurement + `"]}`,
		`{"allowed_measurements":[{"id":"test","measurement":"` + testMeasurement + `"}]}`,
		`{"allowed_measurements":["` + testMeasurement + `"],"constraints":true}`,
	}
	for _, input := range cases {
		if _, err := DecodePolicy([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestPolicyRejectsInvalidMeasurements(t *testing.T) {
	policy := testPolicy()
	policy.AllowedMeasurements = append(policy.AllowedMeasurements, policy.AllowedMeasurements[0])
	if err := policy.Validate(); err == nil {
		t.Fatal("accepted duplicate measurement")
	}
	policy = testPolicy()
	policy.AllowedMeasurements[0] = "ABC"
	if err := policy.Validate(); err == nil {
		t.Fatal("accepted invalid measurement")
	}
	policy = testPolicy()
	policy.AllowedMeasurements[0] = "f" + testMeasurement[1:]
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	err := policy.Authorize(testReport(t))
	if !errors.Is(err, attestation.ErrPolicyDenied) || !strings.Contains(err.Error(), testMeasurement) {
		t.Fatalf("error = %v", err)
	}
}
