package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	guesttesting "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/verirelay/protocol/veriprov1"
	"github.com/verirelay/veriprov/internal/attestation/sevsnp"
)

// legitTCB is above the Milan platform baseline.
var legitTCB = kds.TCBParts{BlSpl: 4, SnpSpl: 0x1d, UcodeSpl: 0xde}

// fakeKDS serves a test AMD certificate chain and, like AMD KDS for a real
// chip, a VCEK at every chip and TCB. It counts the requests per URL.
type fakeKDS struct {
	signer *guesttesting.AmdSigner
	server *httptest.Server

	mu       sync.Mutex
	requests map[string]int
}

func newFakeKDS(t *testing.T) *fakeKDS {
	t.Helper()
	version, err := kds.ComposeTCBParts(legitTCB)
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
		VcekCustom:       guesttesting.CertOverride{Extensions: guesttesting.CustomExtensions(legitTCB, testChipID[:], "go-sev-guest", "Milan-B1")},
	}
	signer, err := builder.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Product, err = kds.ParseProductName("Milan-B1", abi.VcekReportSigner); err != nil {
		t.Fatal(err)
	}
	certs, err := guesttesting.FakeKDSFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeKDS{signer: signer, requests: map[string]int{}}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fake.mu.Lock()
		fake.requests[request.URL.RequestURI()]++
		fake.mu.Unlock()
		if strings.HasSuffix(request.URL.Path, "/cert_chain") {
			body, _ := certs.Get("https://kdsintf.amd.com" + request.URL.RequestURI())
			_, _ = writer.Write(body)
			return
		}
		_, _ = writer.Write(signer.Vcek.Raw)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// count returns the requests for the VCEK of testChipID at tcb, or all
// requests when tcb is nil.
func (fake *fakeKDS) count(tcb *kds.TCBParts) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if tcb == nil {
		total := 0
		for _, n := range fake.requests {
			total += n
		}
		return total
	}
	version, _ := kds.ComposeTCBParts(*tcb)
	return fake.requests[strings.TrimPrefix(kds.VCEKCertURL("Milan", testChipID[:], version), "https://kdsintf.amd.com")]
}

// newServer returns a test server whose verifier fetches from this KDS and
// caches in cacheDir.
func (fake *fakeKDS) newServer(t *testing.T, cacheDir string) testServer {
	t.Helper()
	getter, err := sevsnp.NewKDSGetter(sevsnp.KDSGetterOptions{MaxAttempts: 1, TestBaseURL: fake.server.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sevsnp.NewVerifier(sevsnp.VerifierOptions{
		Policy:         sevsnp.Policy{AllowedMeasurements: []string{strings.Repeat("07", abi.MeasurementSize)}},
		AllowedChipIDs: [][abi.ChipIDSize]byte{testChipID},
		Getter:         getter,
		TrustedRoots: map[string][]*trust.AMDRootCerts{
			"Milan": {{Product: "Milan", ProductLine: "Milan", ProductCerts: &trust.ProductCerts{Ask: fake.signer.Ask, Ark: fake.signer.Ark}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer(t, verifier)
}

// provision sends a provision request with a report for chipID at tcb, signed
// by the fake KDS's chip when signed is true, and returns the status.
func (fake *fakeKDS) provision(t *testing.T, server testServer, chipID [abi.ChipIDSize]byte, tcb kds.TCBParts, signed bool) int {
	t.Helper()
	var challenge veriprov1.ChallengeResponse
	if err := json.Unmarshal(server.do(t, http.MethodPost, "/v1/challenge", []byte(`{}`)).Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	nonce, err := veriprov1.DecodeBase64URL(challenge.Nonce, "nonce", -1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reportData, err := veriprov1.ReportData(nonce, key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	version, err := kds.ComposeTCBParts(tcb)
	if err != nil {
		t.Fatal(err)
	}
	raw := guesttesting.CreateRawReport(&guesttesting.TestReportOptions{ReportData: reportData[:], SignerInfo: abi.SignerInfo{SigningKey: abi.VcekReportSigner}, FMS: abi.MaskedCpuid1EaxFromSevProduct(fake.signer.Product), Version: 3})
	report, err := abi.ReportToProto(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	report.Policy = 1<<17 | 1<<16
	report.Measurement = bytes.Repeat([]byte{7}, abi.MeasurementSize)
	report.HostData = testHostData[:]
	report.ChipId = chipID[:]
	report.PlatformInfo = 0x25
	report.ReportedTcb, report.CurrentTcb, report.CommittedTcb, report.LaunchTcb = uint64(version), uint64(version), uint64(version), uint64(version)
	reportBytes, err := abi.ReportToAbiBytes(report)
	if err != nil {
		t.Fatal(err)
	}
	if signed {
		r, s, err := fake.signer.Sign(abi.SignedComponent(reportBytes))
		if err != nil {
			t.Fatal(err)
		}
		if err := abi.SetSignature(r, s, reportBytes); err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(veriprov1.ProvisionRequest{
		ChallengeID:           challenge.ChallengeID,
		ProvisioningPublicKey: veriprov1.EncodeBase64URL(key.PublicKey().Bytes()),
		AttestationReport:     veriprov1.EncodeBase64URL(reportBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.do(t, http.MethodPost, "/v1/provision", body).Code
}

func TestProvisionUnlistedChipNeverReachesKDS(t *testing.T) {
	fake := newFakeKDS(t)
	server := fake.newServer(t, "")
	unlisted := [abi.ChipIDSize]byte(bytes.Repeat([]byte{0x5a}, abi.ChipIDSize))
	for range 50 {
		if status := fake.provision(t, server, unlisted, legitTCB, false); status != http.StatusConflict {
			t.Fatalf("status = %d, want 409", status)
		}
	}
	if got := fake.count(nil); got != 0 {
		t.Fatalf("AMD KDS requests = %d, want 0", got)
	}
}

func TestForgedReportsDoNotEvictVerifiedVCEK(t *testing.T) {
	fake := newFakeKDS(t)
	cacheDir := t.TempDir()
	server := fake.newServer(t, cacheDir)
	for range 2 {
		if status := fake.provision(t, server, testChipID, legitTCB, true); status != http.StatusOK {
			t.Fatalf("legitimate provision status = %d, want 200", status)
		}
	}
	if got := fake.count(&legitTCB); got != 1 {
		t.Fatalf("legitimate VCEK requests = %d, want 1", got)
	}
	// More forged reports than either cache holds, each at a distinct TCB of
	// the allowed chip.
	const forged = 300
	for i := range forged {
		tcb := kds.TCBParts{BlSpl: uint8(i % 128), SnpSpl: uint8(i / 128), UcodeSpl: 1}
		if status := fake.provision(t, server, testChipID, tcb, false); status != http.StatusConflict {
			t.Fatalf("forged provision status = %d, want 409", status)
		}
	}
	restarted := fake.newServer(t, cacheDir)
	for _, server := range []testServer{server, restarted} {
		if status := fake.provision(t, server, testChipID, legitTCB, true); status != http.StatusOK {
			t.Fatalf("legitimate provision status = %d, want 200", status)
		}
	}
	if got := fake.count(&legitTCB); got != 1 {
		t.Fatalf("legitimate VCEK requests after %d forged reports = %d, want 1", forged, got)
	}
}
