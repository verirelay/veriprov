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

	platformSMT        = 1 << 0
	platformTSME       = 1 << 1
	platformECC        = 1 << 2
	platformAliasCheck = 1 << 5
	platformTIO        = 1 << 7
)

var (
	testChipID  = [abi.ChipIDSize]byte(bytes.Repeat([]byte{0xa1}, abi.ChipIDSize))
	otherChipID = [abi.ChipIDSize]byte(bytes.Repeat([]byte{0xb2}, abi.ChipIDSize))
	// testTCB is above the Milan platform baseline (SNP 0x1b, microcode 0xde).
	testTCB = kds.TCBParts{BlSpl: 4, SnpSpl: 0x1d, UcodeSpl: 0xde}
)

type signedVCEKFixture struct {
	report       []byte
	hostData     [abi.HostDataSize]byte
	policy       Policy
	getter       *KDSGetter
	trustedRoots map[string][]*trust.AMDRootCerts
	requestCount *atomic.Int32
	vcekRequests *atomic.Int32
}

type fixtureOptions struct {
	// tcb is the TCB of the signing chip; nil means testTCB.
	tcb *kds.TCBParts
	// mutate edits the report before it is signed.
	mutate func(*sevsnppb.Report)
	// crl returns the CRL body KDS serves; nil serves none.
	crl func(*guesttesting.AmdSigner) []byte
	// anyVCEK makes KDS serve the signer's VCEK at every VCEK URL.
	anyVCEK bool
}

func (fixture signedVCEKFixture) verifier(t *testing.T, checkRevocations bool) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierOptions{Policy: fixture.policy, AllowedChipIDs: [][abi.ChipIDSize]byte{testChipID}, Getter: fixture.getter, CheckRevocations: checkRevocations, TrustedRoots: fixture.trustedRoots})
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
	verified, err := fixture.verifier(t, true).Verify(context.Background(), fixture.report, expected)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if verified.HostData != fixture.hostData || verified.ChipID != testChipID {
		t.Fatalf("Verify() = %+v, want HOST_DATA %x and CHIP_ID %x", verified, fixture.hostData, testChipID)
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

func TestVerifierRejectsInvalidEvidence(t *testing.T) {
	expected := [64]byte{2}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{})
	edited := func(offset int) []byte {
		report := bytes.Clone(fixture.report)
		report[offset] ^= 0xff
		return report
	}
	cases := []struct {
		name     string
		report   []byte
		verifier func(*testing.T) *Verifier
	}{
		{"signature", edited(0x2A0), nil},
		{"measurement edited after signing", edited(0x90), nil},
		{"HOST_DATA edited after signing", edited(0xC0), nil},
		{"test chain under AMD roots", fixture.report, func(t *testing.T) *Verifier {
			fixture := fixture
			fixture.trustedRoots = nil
			return fixture.verifier(t, false)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			verifier := fixture.verifier(t, false)
			if test.verifier != nil {
				verifier = test.verifier(t)
			}
			if _, err := verifier.Verify(context.Background(), test.report, expected); !errors.Is(err, attestation.ErrInvalidEvidence) {
				t.Fatalf("Verify() error = %v, want ErrInvalidEvidence", err)
			}
		})
	}
}

func TestVerifierPolicyDenials(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sevsnppb.Report)
		policy  func(*Policy)
		anyVCEK bool
	}{
		{name: "debug", mutate: func(report *sevsnppb.Report) { report.Policy |= policyDebug }},
		{name: "migration agent", mutate: func(report *sevsnppb.Report) { report.Policy |= policyMigrate }},
		{name: "VMPL 1", mutate: func(report *sevsnppb.Report) { report.Vmpl = 1 }},
		{name: "VMPL 3", mutate: func(report *sevsnppb.Report) { report.Vmpl = 3 }},
		{name: "committed TCB differs", mutate: func(report *sevsnppb.Report) { report.CommittedTcb++ }},
		{name: "REPORTED_TCB differs from the VCEK", anyVCEK: true, mutate: func(report *sevsnppb.Report) { report.ReportedTcb++ }},
		{name: "measurement", policy: func(policy *Policy) { policy.AllowedMeasurements = []string{strings.Repeat("0", 96)} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expected := [64]byte{6}
			fixture := newSignedVCEKFixture(t, expected, fixtureOptions{mutate: test.mutate, anyVCEK: test.anyVCEK})
			if test.policy != nil {
				test.policy(&fixture.policy)
			}
			if _, err := fixture.verifier(t, false).Verify(context.Background(), fixture.report, expected); !errors.Is(err, attestation.ErrPolicyDenied) {
				t.Fatalf("Verify() error = %v, want ErrPolicyDenied", err)
			}
		})
	}
}

func TestVerifierRefusesChipIDOfAnotherVCEK(t *testing.T) {
	expected := [64]byte{6}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{anyVCEK: true, mutate: func(report *sevsnppb.Report) { report.ChipId = otherChipID[:] }})
	verifier, err := NewVerifier(VerifierOptions{Policy: fixture.policy, AllowedChipIDs: [][abi.ChipIDSize]byte{otherChipID}, Getter: fixture.getter, TrustedRoots: fixture.trustedRoots})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), fixture.report, expected)
	if !errors.Is(err, attestation.ErrPolicyDenied) || !strings.Contains(err.Error(), "HWID") {
		t.Fatalf("Verify() error = %v, want ErrPolicyDenied naming the VCEK HWID", err)
	}
}

func TestNewVerifierRequiresAllowedChipIDs(t *testing.T) {
	fixture := newSignedVCEKFixture(t, [64]byte{6}, fixtureOptions{})
	if _, err := NewVerifier(VerifierOptions{Policy: fixture.policy, Getter: fixture.getter}); err == nil {
		t.Fatal("NewVerifier() accepted no allowed CHIP_IDs")
	}
}

func TestVerifierRefusesUnlistedChipBeforeKDS(t *testing.T) {
	expected := [64]byte{6}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{})
	verifier, err := NewVerifier(VerifierOptions{Policy: fixture.policy, AllowedChipIDs: [][abi.ChipIDSize]byte{otherChipID}, Getter: fixture.getter, TrustedRoots: fixture.trustedRoots})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), fixture.report, expected); !errors.Is(err, attestation.ErrPolicyDenied) {
		t.Fatalf("Verify() error = %v, want ErrPolicyDenied", err)
	}
	if fixture.requestCount.Load() != 0 {
		t.Fatalf("KDS requests = %d, want 0", fixture.requestCount.Load())
	}
}

func TestVerifierPlatformBaseline(t *testing.T) {
	tcb := func(parts kds.TCBParts) *kds.TCBParts { return &parts }
	cases := []struct {
		name    string
		tcb     *kds.TCBParts
		mutate  func(*sevsnppb.Report)
		allowed bool
	}{
		{name: "at the minimum", tcb: tcb(kds.TCBParts{SnpSpl: 0x1b, UcodeSpl: 0xde}), allowed: true},
		{name: "SMT, TSME and SEV-TIO", mutate: func(report *sevsnppb.Report) { report.PlatformInfo |= platformTSME | platformTIO }, allowed: true},
		{name: "TCB 0", tcb: tcb(kds.TCBParts{})},
		{name: "microcode below the minimum", tcb: tcb(kds.TCBParts{BlSpl: 4, SnpSpl: 0x1d, UcodeSpl: 0xdd})},
		{name: "SNP firmware below the minimum", tcb: tcb(kds.TCBParts{BlSpl: 4, SnpSpl: 0x1a, UcodeSpl: 0xde})},
		{name: "LAUNCH_TCB below the minimum", mutate: func(report *sevsnppb.Report) { report.LaunchTcb &^= 0xff << 56 }},
		{name: "alias check incomplete", mutate: func(report *sevsnppb.Report) { report.PlatformInfo &^= platformAliasCheck }},
		{name: "CPU model without a baseline", mutate: func(report *sevsnppb.Report) { report.Cpuid1EaxFms = 0x00a00f10 }},
		{name: "report version 2", mutate: func(report *sevsnppb.Report) { report.Version, report.Cpuid1EaxFms = 2, 0 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expected := [64]byte{8}
			fixture := newSignedVCEKFixture(t, expected, fixtureOptions{tcb: test.tcb, mutate: test.mutate})
			_, err := fixture.verifier(t, false).Verify(context.Background(), fixture.report, expected)
			if test.allowed {
				if err != nil {
					t.Fatalf("Verify() = %v", err)
				}
				return
			}
			if !errors.Is(err, attestation.ErrPolicyDenied) || !strings.Contains(err.Error(), "platform baseline") {
				t.Fatalf("Verify() error = %v, want a platform baseline denial", err)
			}
		})
	}
}

func TestVerifierCachesVCEKOnlyOnceAReportVerified(t *testing.T) {
	expected := [64]byte{9}
	fixture := newSignedVCEKFixture(t, expected, fixtureOptions{})
	verifier := fixture.verifier(t, false)
	forged := bytes.Clone(fixture.report)
	forged[0x2A0] ^= 0xff
	for range 2 {
		if _, err := verifier.Verify(context.Background(), forged, expected); !errors.Is(err, attestation.ErrInvalidEvidence) {
			t.Fatalf("Verify(forged) error = %v, want ErrInvalidEvidence", err)
		}
	}
	if got := fixture.vcekRequests.Load(); got != 2 {
		t.Fatalf("VCEK requests after two forged reports = %d, want 2", got)
	}
	for range 2 {
		if _, err := verifier.Verify(context.Background(), fixture.report, expected); err != nil {
			t.Fatalf("Verify() = %v", err)
		}
	}
	if got := fixture.vcekRequests.Load(); got != 3 {
		t.Fatalf("VCEK requests after two verified reports = %d, want 3", got)
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

// newSigner returns a test AMD certificate chain for a Milan-B1 chip with
// CHIP_ID testChipID at tcb.
func newSigner(t *testing.T, tcb kds.TCBParts) *guesttesting.AmdSigner {
	t.Helper()
	version, err := kds.ComposeTCBParts(tcb)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	builder := &guesttesting.AmdSignerBuilder{
		Keys:             guesttesting.DefaultAmdKeys(),
		ProductName:      "Milan-B1",
		CSPID:            "go-sev-guest",
		ArkCreationTime:  now,
		AskCreationTime:  now,
		AsvkCreationTime: now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		HWID:             testChipID,
		TCB:              version,
		VcekCustom:       guesttesting.CertOverride{Extensions: guesttesting.CustomExtensions(tcb, testChipID[:], "go-sev-guest", "Milan-B1")},
	}
	signer, err := builder.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Product, err = kds.ParseProductName("Milan-B1", abi.VcekReportSigner); err != nil {
		t.Fatal(err)
	}
	return signer
}

func newSignedVCEKFixture(t *testing.T, expected [64]byte, options fixtureOptions) signedVCEKFixture {
	t.Helper()
	tcb := testTCB
	if options.tcb != nil {
		tcb = *options.tcb
	}
	signer := newSigner(t, tcb)
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
	report.PlatformInfo = platformSMT | platformECC | platformAliasCheck
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
	vcekRequests := &atomic.Int32{}
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
		requestURL := "https://kdsintf.amd.com" + request.URL.RequestURI()
		if isVCEKURL(requestURL) {
			vcekRequests.Add(1)
			if options.anyVCEK {
				_, _ = writer.Write(signer.Vcek.Raw)
				return
			}
		}
		body, getErr := fakeKDS.Get(requestURL)
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
		vcekRequests: vcekRequests,
	}
}
