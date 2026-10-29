package sevsnp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	guesttesting "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/verirelay/veriprov/internal/attestation"
)

const (
	policyReserved = 1 << 17
	policySMT      = 1 << 16
	policyMigrate  = 1 << 18
	policyDebug    = 1 << 19
)

type signedVCEKFixture struct {
	report       []byte
	hostData     [abi.HostDataSize]byte
	policy       Policy
	getter       *KDSGetter
	trustedRoots map[string][]*trust.AMDRootCerts
	requestCount *atomic.Int32
}

type fixtureOptions struct {
	// mutate edits the report before it is signed.
	mutate func(*sevsnppb.Report)
	// crl returns the CRL body KDS serves; nil serves none.
	crl func(*guesttesting.AmdSigner) []byte
}

func (fixture signedVCEKFixture) verifier(t *testing.T, checkRevocations bool) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierOptions{Policy: fixture.policy, Getter: fixture.getter, CheckRevocations: checkRevocations, TrustedRoots: fixture.trustedRoots})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func currentCRL(signer *guesttesting.AmdSigner) []byte {
	return signedCRL(signer, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func signedCRL(signer *guesttesting.AmdSigner, thisUpdate, nextUpdate time.Time) []byte {
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate}, signer.Ark, signer.Keys.Ark)
	if err != nil {
		panic(err)
	}
	return crl
}

func TestVerifierAcceptsSignedVCEKFromServerKDS(t *testing.T) {
	expected := [64]byte{1}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{
		mutate: func(report *sevsnppb.Report) { report.Policy |= policySMT },
		crl:    currentCRL,
	})
	hostData, err := fixture.verifier(t, true).Verify(context.Background(), fixture.report, expected)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if hostData != fixture.hostData {
		t.Fatalf("HOST_DATA = %x, want %x", hostData, fixture.hostData)
	}
	if fixture.requestCount.Load() == 0 {
		t.Fatal("verifier did not fetch server-controlled KDS endorsements")
	}
}

func TestVerifierRejectsReportDataMismatch(t *testing.T) {
	fixture := newSignedVCEKFixture(t, [64]byte{2}, fixtureOptions{})
	if _, err := fixture.verifier(t, false).Verify(context.Background(), fixture.report, [64]byte{3}); !errors.Is(err, attestation.ErrReportDataMismatch) {
		t.Fatalf("Verify() error = %v, want ErrReportDataMismatch", err)
	}
}

func TestVerifierRejectsTamperedSignature(t *testing.T) {
	expected := [64]byte{2}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{})
	report := bytes.Clone(fixture.report)
	report[0x2A0] ^= 0xff
	if _, err := fixture.verifier(t, false).Verify(context.Background(), report, expected); !errors.Is(err, attestation.ErrInvalidEvidence) {
		t.Fatalf("Verify() error = %v, want ErrInvalidEvidence", err)
	}
}

func TestVerifierPolicyDenials(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*sevsnppb.Report)
		policy func(*Policy)
	}{
		{name: "debug", mutate: func(report *sevsnppb.Report) { report.Policy |= policyDebug }},
		{name: "migration agent", mutate: func(report *sevsnppb.Report) { report.Policy |= policyMigrate }},
		{name: "VMPL 1", mutate: func(report *sevsnppb.Report) { report.Vmpl = 1 }},
		{name: "committed TCB differs", mutate: func(report *sevsnppb.Report) { report.CommittedTcb++ }},
		{name: "measurement", policy: func(policy *Policy) { policy.AllowedMeasurements = []string{strings.Repeat("0", 96)} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expected := [64]byte{6}
			fixture := newSignedVCEKFixture(t, expected, fixtureOptions{mutate: test.mutate})
			if test.policy != nil {
				test.policy(&fixture.policy)
			}
			if _, err := fixture.verifier(t, false).Verify(context.Background(), fixture.report, expected); !errors.Is(err, attestation.ErrPolicyDenied) {
				t.Fatalf("Verify() error = %v, want ErrPolicyDenied", err)
			}
		})
	}
}

func TestVerifierRequiresCurrentCRL(t *testing.T) {
	cases := []struct {
		name string
		crl  func(*guesttesting.AmdSigner) []byte
	}{
		{"missing", nil},
		{"expired", func(signer *guesttesting.AmdSigner) []byte {
			return signedCRL(signer, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		}},
		{"not yet valid", func(signer *guesttesting.AmdSigner) []byte {
			return signedCRL(signer, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expected := [64]byte{7}
			fixture := newSignedVCEKFixture(t, expected, fixtureOptions{crl: test.crl})
			if _, err := fixture.verifier(t, true).Verify(context.Background(), fixture.report, expected); !errors.Is(err, attestation.ErrDependencyUnavailable) {
				t.Fatalf("Verify() error = %v, want ErrDependencyUnavailable", err)
			}
		})
	}
}

func TestParseReportRejectsMalformedReports(t *testing.T) {
	fixture := newSignedVCEKFixture(t, [64]byte{1}, fixtureOptions{})
	mutated := func(edit func([]byte)) []byte {
		report := bytes.Clone(fixture.report)
		edit(report)
		return report
	}
	signer := func(key abi.ReportSigner) func([]byte) {
		return func(report []byte) {
			binary.LittleEndian.PutUint32(report[0x48:], abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: key}))
		}
	}
	cases := []struct {
		name     string
		report   []byte
		sentinel error
	}{
		{"short", fixture.report[:abi.ReportSize-1], attestation.ErrMalformedReport},
		{"long", append(bytes.Clone(fixture.report), 0), attestation.ErrMalformedReport},
		{"unsupported version", mutated(func(report []byte) { binary.LittleEndian.PutUint32(report, 1) }), attestation.ErrMalformedReport},
		{"invalid guest policy", mutated(func(report []byte) { report[0x0A] &^= 0x02 }), attestation.ErrMalformedReport},
		{"reserved bytes set", mutated(func(report []byte) { report[0x4C] = 1 }), attestation.ErrMalformedReport},
		{"invalid signer info", mutated(func(report []byte) { report[0x48] |= 1 << 5 }), attestation.ErrMalformedReport},
		{"VLEK signer", mutated(signer(abi.VlekReportSigner)), attestation.ErrPolicyDenied},
		{"no signer", mutated(signer(abi.NoneReportSigner)), attestation.ErrPolicyDenied},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report, err := parseReport(test.report)
			if !errors.Is(err, test.sentinel) {
				t.Fatalf("parseReport() error = %v, want %v", err, test.sentinel)
			}
			if report != nil {
				t.Fatalf("parseReport() report = %v, want nil", report)
			}
		})
	}
	if _, err := parseReport(fixture.report); err != nil {
		t.Fatalf("parseReport(valid report) error = %v", err)
	}
}

func TestClassifyVerificationErrorWrapsCause(t *testing.T) {
	cause := errors.New("sentinel")
	err := classifyVerificationError(cause)
	if !errors.Is(err, attestation.ErrInvalidEvidence) || !errors.Is(err, cause) {
		t.Fatalf("classifyVerificationError(cause) = %v", err)
	}
	err = classifyVerificationError(&trust.AttestationRecreationErr{Msg: "could not download VCEK certificate"})
	if !errors.Is(err, attestation.ErrDependencyUnavailable) {
		t.Fatalf("classifyVerificationError(recreation) = %v", err)
	}
	err = classifyVerificationError(context.Canceled)
	if !errors.Is(err, attestation.ErrDependencyUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("classifyVerificationError(context.Canceled) = %v", err)
	}
}

func newSignedVCEKFixture(t *testing.T, expected [64]byte, options fixtureOptions) signedVCEKFixture {
	t.Helper()
	signer, err := guesttesting.DefaultTestOnlyCertChain("Milan-B0", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signer.Product, err = kds.ParseProductName("Milan-B0", abi.VcekReportSigner)
	if err != nil {
		t.Fatal(err)
	}
	fms := abi.MaskedCpuid1EaxFromSevProduct(signer.Product)
	raw := guesttesting.CreateRawReport(&guesttesting.TestReportOptions{ReportData: expected[:], SignerInfo: abi.SignerInfo{SigningKey: abi.VcekReportSigner}, FMS: fms, Version: 3})
	report, err := abi.ReportToProto(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	report.Policy = policyReserved
	report.GuestSvn = 1
	report.Vmpl = 0
	report.Measurement = bytes.Repeat([]byte{7}, abi.MeasurementSize)
	report.HostData = bytes.Repeat([]byte{9}, abi.HostDataSize)
	report.ChipId = append([]byte(nil), signer.HWID[:]...)
	report.CurrentTcb = uint64(signer.TCB)
	report.ReportedTcb = uint64(signer.TCB)
	report.CommittedTcb = uint64(signer.TCB)
	report.LaunchTcb = uint64(signer.TCB)
	measurement := hex.EncodeToString(report.Measurement)
	if options.mutate != nil {
		options.mutate(report)
	}
	unsigned, err := abi.ReportToAbiBytes(report)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := signer.Sign(abi.SignedComponent(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	if err := abi.SetSignature(r, s, unsigned); err != nil {
		t.Fatal(err)
	}
	fakeKDS, err := guesttesting.FakeKDSFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	var crl []byte
	if options.crl != nil {
		crl = options.crl(signer)
	}
	crlPath := strings.TrimPrefix(kds.CrlLinkByKey("Milan", abi.VcekReportSigner), "https://kdsintf.amd.com")
	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.URL.Path == crlPath {
			if crl == nil {
				http.NotFound(writer, request)
				return
			}
			_, _ = writer.Write(crl)
			return
		}
		body, getErr := fakeKDS.Get("https://kdsintf.amd.com" + request.URL.RequestURI())
		if getErr != nil {
			http.Error(writer, getErr.Error(), http.StatusNotFound)
			return
		}
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	getter, err := NewKDSGetter(KDSGetterOptions{AllowedProducts: []string{"Milan"}, MaxAttempts: 1, TestBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	trustedRoots := map[string][]*trust.AMDRootCerts{
		"Milan": {{Product: "Milan", ProductLine: "Milan", ProductCerts: &trust.ProductCerts{Ask: signer.Ask, Ark: signer.Ark, Asvk: signer.Asvk}}},
	}
	return signedVCEKFixture{
		report:       unsigned,
		hostData:     [abi.HostDataSize]byte(report.HostData),
		policy:       Policy{AllowedMeasurements: []string{measurement}},
		getter:       getter,
		trustedRoots: trustedRoots,
		requestCount: requestCount,
	}
}
