package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verirelay/protocol/veriprov1"
	"github.com/verirelay/veriprov/internal/attestation"
	"github.com/verirelay/veriprov/internal/challenge"
)

var (
	testHostData      = [32]byte{9}
	testRuntimeConfig = []byte(`{"version":"verirelay-runtime-config/1","admin_token":"test-only-admin-token"}`)
)

type testVerifier struct {
	hostData [32]byte
	err      error
}

func (verifier testVerifier) Verify(context.Context, []byte, [64]byte) ([32]byte, error) {
	return verifier.hostData, verifier.err
}

type testServer struct {
	handler    *Handler
	challenges *challenge.Issuer
	identity   ed25519.PrivateKey
}

func newTestServer(t *testing.T, verifier attestation.Verifier) testServer {
	t.Helper()
	challenges, err := challenge.NewIssuer(bytes.Repeat([]byte{1}, challenge.KeySize), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Challenges:     challenges,
		Verifier:       verifier,
		IdentityKey:    identity,
		Deployments:    map[[32]byte][]byte{testHostData: testRuntimeConfig},
		MaxBodyBytes:   1 << 20,
		MaxConcurrency: 1,
		Logger:         slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return testServer{handler: handler, challenges: challenges, identity: identity}
}

func (server testServer) do(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.handler.ServeHTTP(response, request)
	return response
}

func (server testServer) challenge(t *testing.T, now time.Time) string {
	t.Helper()
	item, err := server.challenges.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	return veriprov1.EncodeBase64URL(item.ID)
}

func errorCode(t *testing.T, response *httptest.ResponseRecorder) veriprov1.ErrorCode {
	t.Helper()
	var payload veriprov1.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Error.Code
}

func provisionBody(challengeID string, publicKey []byte) []byte {
	body, err := json.Marshal(map[string]string{
		"challenge_id":            challengeID,
		"provisioning_public_key": veriprov1.EncodeBase64URL(publicKey),
		"attestation_report":      veriprov1.EncodeBase64URL(bytes.Repeat([]byte{1}, veriprov1.AttestationReportSize)),
		"future_field":            "ignored",
	})
	if err != nil {
		panic(err)
	}
	return body
}

func TestHealthEndpoints(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: testHostData})
	for _, path := range []string{"/healthz", "/readyz"} {
		if response := server.do(t, http.MethodGet, path, nil); response.Code != http.StatusOK || response.Body.String() != "ok\n" {
			t.Fatalf("GET %s = %d %q", path, response.Code, response.Body.String())
		}
		if response := server.do(t, http.MethodPost, path, nil); response.Code != http.StatusBadRequest {
			t.Fatalf("POST %s = %d, want 400", path, response.Code)
		}
	}
}

func TestChallengeResponse(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: testHostData})
	response := server.do(t, http.MethodPost, "/v1/challenge", []byte(`{"future_field":1}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var payload veriprov1.ChallengeResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if err := payload.Validate(); err != nil {
		t.Fatal(err)
	}
	if payload.TTLSeconds != 60 {
		t.Fatalf("ttl_seconds = %d, want 60", payload.TTLSeconds)
	}
	id, err := veriprov1.DecodeBase64URL(payload.ChallengeID, "challenge_id", -1)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := server.challenges.Verify(id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if veriprov1.EncodeBase64URL(nonce) != payload.Nonce {
		t.Fatal("challenge_id does not carry the nonce")
	}
}

func TestProvisionReturnsSignedSealedRuntimeConfig(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: testHostData})
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challengeID := server.challenge(t, time.Now())
	for range 2 {
		response := server.do(t, http.MethodPost, "/v1/provision", provisionBody(challengeID, privateKey.PublicKey().Bytes()))
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", response.Code, response.Body.String())
		}
		var payload veriprov1.ProvisionResponse
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if err := payload.Validate(); err != nil {
			t.Fatal(err)
		}
		if payload.Envelope.ChallengeID != challengeID {
			t.Fatalf("challenge_id = %q, want %q", payload.Envelope.ChallengeID, challengeID)
		}
		if err := veriprov1.VerifyEnvelopeSignature(server.identity.Public().(ed25519.PublicKey), payload.Envelope); err != nil {
			t.Fatal(err)
		}
		plaintext, err := veriprov1.Open(privateKey.Bytes(), payload.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, testRuntimeConfig) {
			t.Fatalf("plaintext = %q, want %q", plaintext, testRuntimeConfig)
		}
	}
}

func TestProvisionRejectsUnknownHostData(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: [32]byte{1}})
	response := server.do(t, http.MethodPost, "/v1/provision", provisionBody(server.challenge(t, time.Now()), bytes.Repeat([]byte{1}, veriprov1.X25519PublicKeySize)))
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", response.Code)
	}
	if code := errorCode(t, response); code != veriprov1.ErrPolicyDenied {
		t.Fatalf("code = %q, want %q", code, veriprov1.ErrPolicyDenied)
	}
}

func TestProvisionChallengeErrors(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: testHostData})
	foreign, err := challenge.NewIssuer(bytes.Repeat([]byte{2}, challenge.KeySize), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	foreignItem, err := foreign.Issue(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		challengeID string
		code        veriprov1.ErrorCode
	}{
		{"expired", server.challenge(t, time.Now().Add(-2*time.Minute)), veriprov1.ErrChallengeExpired},
		{"other key", veriprov1.EncodeBase64URL(foreignItem.ID), veriprov1.ErrChallengeNotFound},
		{"random token", veriprov1.EncodeBase64URL(bytes.Repeat([]byte{3}, 16)), veriprov1.ErrChallengeNotFound},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := server.do(t, http.MethodPost, "/v1/provision", provisionBody(test.challengeID, bytes.Repeat([]byte{1}, veriprov1.X25519PublicKeySize)))
			if response.Code != veriprov1.StatusForError(test.code) {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if code := errorCode(t, response); code != test.code {
				t.Fatalf("code = %q, want %q", code, test.code)
			}
		})
	}
}

func TestProvisionAttestationErrorMapping(t *testing.T) {
	cases := []struct {
		name          string
		verifierError error
		code          veriprov1.ErrorCode
	}{
		{"report data", attestation.ErrReportDataMismatch, veriprov1.ErrReportDataMismatch},
		{"policy", attestation.ErrPolicyDenied, veriprov1.ErrPolicyDenied},
		{"invalid evidence", attestation.ErrInvalidEvidence, veriprov1.ErrPolicyDenied},
		{"dependency", attestation.ErrDependencyUnavailable, veriprov1.ErrUnavailable},
		{"malformed", attestation.ErrMalformedReport, veriprov1.ErrInvalidField},
		{"unknown", errors.New("bug"), veriprov1.ErrUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, testVerifier{hostData: testHostData, err: test.verifierError})
			response := server.do(t, http.MethodPost, "/v1/provision", provisionBody(server.challenge(t, time.Now()), bytes.Repeat([]byte{1}, veriprov1.X25519PublicKeySize)))
			if response.Code != veriprov1.StatusForError(test.code) {
				t.Fatalf("status = %d, want %d", response.Code, veriprov1.StatusForError(test.code))
			}
			if code := errorCode(t, response); code != test.code {
				t.Fatalf("code = %q, want %q", code, test.code)
			}
		})
	}
}

func TestProvisionRequestErrors(t *testing.T) {
	server := newTestServer(t, testVerifier{hostData: testHostData})
	valid := provisionBody(server.challenge(t, time.Now()), bytes.Repeat([]byte{1}, veriprov1.X25519PublicKeySize))
	cases := []struct {
		name string
		body []byte
		code veriprov1.ErrorCode
	}{
		{"duplicate key", []byte(`{"challenge_id":"a","challenge_id":"b"}`), veriprov1.ErrMalformedJSON},
		{"trailing data", append(bytes.Clone(valid), []byte(`{}`)...), veriprov1.ErrMalformedJSON},
		{"short report", []byte(strings.Replace(string(valid), `"attestation_report":"AQEB`, `"attestation_report":"AQ`, 1)), veriprov1.ErrInvalidField},
		{"too large", bytes.Repeat([]byte(" "), 1<<20+1), veriprov1.ErrBodyTooLarge},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := server.do(t, http.MethodPost, "/v1/provision", test.body)
			if code := errorCode(t, response); code != test.code {
				t.Fatalf("code = %q, want %q", code, test.code)
			}
		})
	}
}
