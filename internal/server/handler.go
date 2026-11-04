package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/verirelay/protocol/veriprov1"
	"github.com/verirelay/veriprov/internal/attestation"
	"github.com/verirelay/veriprov/internal/challenge"
	"github.com/verirelay/veriprov/internal/config"
)

type Options struct {
	Challenges  *challenge.Issuer
	Verifier    attestation.Verifier
	IdentityKey ed25519.PrivateKey
	// Deployments pair each Bootstrap with the Runtime Config sealed to a
	// Guest whose Attestation Report carries its HOST_DATA and one of its
	// allowed CHIP_IDs.
	Deployments    []config.Deployment
	MaxBodyBytes   int64
	MaxConcurrency int
	Logger         *slog.Logger
}

type Handler struct {
	options     Options
	limit       chan struct{}
	deployments map[[32]byte]config.Deployment
	bootstraps  BootstrapsResponse
}

// BootstrapsResponse is the body of GET /v1/bootstraps: the Bootstrap of every
// deployment, in the order of the deployments file.
type BootstrapsResponse struct {
	Bootstraps []Bootstrap `json:"bootstraps"`
}

// Bootstrap is one deployment's Bootstrap: its profile, its HOST_DATA in hex,
// and its exact file bytes in unpadded base64url.
type Bootstrap struct {
	Profile   string `json:"profile"`
	HostData  string `json:"host_data"`
	Bootstrap string `json:"bootstrap"`
}

func NewHandler(options Options) (*Handler, error) {
	if options.Challenges == nil || options.Verifier == nil {
		return nil, errors.New("challenge issuer and attestation verifier are required")
	}
	if len(options.IdentityKey) != ed25519.PrivateKeySize {
		return nil, errors.New("identity key is required")
	}
	if len(options.Deployments) == 0 {
		return nil, errors.New("at least one deployment is required")
	}
	if options.MaxBodyBytes <= 0 || options.MaxConcurrency <= 0 {
		return nil, errors.New("server limits must be positive")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	handler := &Handler{options: options, limit: make(chan struct{}, options.MaxConcurrency), deployments: map[[32]byte]config.Deployment{}}
	for _, d := range options.Deployments {
		handler.deployments[d.HostData] = d
		handler.bootstraps.Bootstraps = append(handler.bootstraps.Bootstraps, Bootstrap{
			Profile:   d.Profile,
			HostData:  hex.EncodeToString(d.HostData[:]),
			Bootstrap: veriprov1.EncodeBase64URL(d.Bootstrap),
		})
	}
	return handler, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	id := requestID(request)
	writer.Header().Set("X-Request-ID", id)
	select {
	case handler.limit <- struct{}{}:
		defer func() { <-handler.limit }()
	default:
		handler.writeError(writer, veriprov1.ErrUnavailable, "server concurrency limit reached", id)
		return
	}
	defer func() {
		if recover() != nil {
			handler.options.Logger.Error("recovered panic", "request_id", id)
			handler.writeError(writer, veriprov1.ErrInternal, "internal server error", id)
		}
	}()
	switch request.URL.Path {
	case "/healthz", "/readyz":
		handler.health(writer, request, id)
	case "/v1/challenge":
		handler.createChallenge(writer, request, id)
	case "/v1/provision":
		handler.provision(writer, request, id)
	case "/v1/bootstraps":
		handler.listBootstraps(writer, request, id)
	default:
		handler.writeError(writer, veriprov1.ErrInvalidField, "route not found", id)
	}
}

func (handler *Handler) health(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(writer, id)
		return
	}
	_, _ = writer.Write([]byte("ok\n"))
}

// listBootstraps serves the Bootstraps, which are public: a CVM discloses its
// own in every attestation response. Hosts fetch them to launch CVMs with the
// exact bytes.
func (handler *Handler) listBootstraps(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(writer, id)
		return
	}
	handler.writeJSON(writer, http.StatusOK, handler.bootstraps)
}

func (handler *Handler) createChallenge(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(writer, id)
		return
	}
	if !jsonContentType(request) {
		handler.writeError(writer, veriprov1.ErrInvalidField, "Content-Type must be application/json", id)
		return
	}
	var payload veriprov1.ChallengeRequest
	if !handler.decode(writer, request, &payload, id) {
		return
	}
	item, err := handler.options.Challenges.Issue(time.Now())
	if err != nil {
		handler.options.Logger.Error("challenge creation failed", "request_id", id, "error", err)
		handler.writeError(writer, veriprov1.ErrInternal, "could not create challenge", id)
		return
	}
	ttlSeconds := int(item.ExpiresAt.Sub(item.IssuedAt) / time.Second)
	handler.options.Logger.Info("challenge created", "request_id", id, "ttl_seconds", ttlSeconds)
	handler.writeJSON(writer, http.StatusOK, veriprov1.ChallengeResponse{
		ChallengeID: veriprov1.EncodeBase64URL(item.ID),
		Nonce:       veriprov1.EncodeBase64URL(item.Nonce),
		IssuedAt:    veriprov1.FormatUTCTime(item.IssuedAt),
		ExpiresAt:   veriprov1.FormatUTCTime(item.ExpiresAt),
		TTLSeconds:  ttlSeconds,
	})
}

func (handler *Handler) provision(writer http.ResponseWriter, request *http.Request, id string) {
	startedAt := time.Now()
	handler.options.Logger.Info("provision request received", "request_id", id, "body_bytes", request.ContentLength)
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(writer, id)
		return
	}
	if !jsonContentType(request) {
		handler.writeError(writer, veriprov1.ErrInvalidField, "Content-Type must be application/json", id)
		return
	}
	var payload veriprov1.ProvisionRequest
	if !handler.decode(writer, request, &payload, id) {
		return
	}
	if err := payload.Validate(); err != nil {
		handler.writeError(writer, veriprov1.ErrInvalidField, err.Error(), id)
		return
	}
	challengeID, _ := veriprov1.DecodeBase64URL(payload.ChallengeID, "challenge_id", -1)
	nonce, err := handler.options.Challenges.Verify(challengeID, time.Now())
	if err != nil {
		handler.challengeError(writer, err, id)
		return
	}
	publicKey, _ := veriprov1.DecodeBase64URL(payload.ProvisioningPublicKey, "provisioning_public_key", veriprov1.X25519PublicKeySize)
	expected, err := veriprov1.ReportData(nonce, publicKey)
	if err != nil {
		handler.writeError(writer, veriprov1.ErrInvalidField, err.Error(), id)
		return
	}
	report, _ := veriprov1.DecodeBase64URL(payload.AttestationReport, "attestation_report", veriprov1.AttestationReportSize)
	verified, err := handler.options.Verifier.Verify(request.Context(), report, expected)
	if err != nil {
		handler.attestationError(writer, err, id)
		return
	}
	hostData, chipID := hex.EncodeToString(verified.HostData[:]), hex.EncodeToString(verified.ChipID[:])
	d, ok := handler.deployments[verified.HostData]
	if !ok {
		handler.options.Logger.Warn("provision rejected: unknown HOST_DATA", "request_id", id, "host_data", hostData, "chip_id", chipID)
		handler.writeError(writer, veriprov1.ErrPolicyDenied, "HOST_DATA matches no deployment", id)
		return
	}
	if !slices.Contains(d.AllowedChipIDs, verified.ChipID) {
		handler.options.Logger.Warn("provision rejected: CHIP_ID not in the deployment's allowed_chip_ids", "request_id", id, "host_data", hostData, "chip_id", chipID)
		handler.writeError(writer, veriprov1.ErrPolicyDenied, "CHIP_ID is not allowed for this deployment", id)
		return
	}
	handler.options.Logger.Info("attestation verification succeeded", "request_id", id, "host_data", hostData, "chip_id", chipID, "duration_ms", time.Since(startedAt).Milliseconds())
	response, err := handler.seal(publicKey, d.RuntimeConfig, payload.ChallengeID)
	if err != nil {
		handler.options.Logger.Error("seal runtime config failed", "request_id", id, "error", err)
		handler.writeError(writer, veriprov1.ErrHPKEFailure, "could not seal runtime config", id)
		return
	}
	handler.options.Logger.Info("runtime config sealed", "request_id", id, "duration_ms", time.Since(startedAt).Milliseconds())
	handler.writeJSON(writer, http.StatusOK, response)
}

// seal seals runtimeConfig to publicKey and signs the envelope with the
// identity key.
func (handler *Handler) seal(publicKey, runtimeConfig []byte, challengeID string) (veriprov1.ProvisionResponse, error) {
	envelope, err := veriprov1.Seal(publicKey, runtimeConfig, veriprov1.AADContext{Protocol: veriprov1.ProtocolVersion, ChallengeID: challengeID})
	if err != nil {
		return veriprov1.ProvisionResponse{}, err
	}
	if err := veriprov1.SignEnvelope(handler.options.IdentityKey, &envelope); err != nil {
		return veriprov1.ProvisionResponse{}, err
	}
	response := veriprov1.ProvisionResponse{Envelope: envelope}
	return response, response.Validate()
}

func (handler *Handler) decode(writer http.ResponseWriter, request *http.Request, output any, id string) bool {
	data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, handler.options.MaxBodyBytes))
	if err != nil {
		code := veriprov1.ErrMalformedJSON
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			code = veriprov1.ErrBodyTooLarge
		}
		handler.writeError(writer, code, "invalid JSON request", id)
		return false
	}
	if err := veriprov1.DecodeJSON(data, output); err != nil {
		handler.writeError(writer, veriprov1.ErrMalformedJSON, "invalid JSON request", id)
		return false
	}
	return true
}

func (handler *Handler) attestationError(writer http.ResponseWriter, err error, id string) {
	errorClass := "unknown"
	code := veriprov1.ErrUnavailable
	message := "attestation verification dependency is unavailable"
	switch {
	case errors.Is(err, attestation.ErrReportDataMismatch):
		errorClass, code, message = "report_data_mismatch", veriprov1.ErrReportDataMismatch, "attestation report_data did not match challenge binding"
	case errors.Is(err, attestation.ErrMalformedReport):
		errorClass, code, message = "malformed_report", veriprov1.ErrInvalidField, "attestation report is invalid"
	case errors.Is(err, attestation.ErrInvalidEvidence), errors.Is(err, attestation.ErrPolicyDenied):
		errorClass, code, message = "policy_denied", veriprov1.ErrPolicyDenied, "attestation policy denied the report"
	case errors.Is(err, attestation.ErrDependencyUnavailable):
		errorClass = "dependency_unavailable"
	}
	handler.options.Logger.Warn("attestation verification failed", "request_id", id, "error_class", errorClass, "error", err)
	handler.writeError(writer, code, message, id)
}

func (handler *Handler) challengeError(writer http.ResponseWriter, err error, id string) {
	if errors.Is(err, challenge.ErrExpired) {
		handler.writeError(writer, veriprov1.ErrChallengeExpired, "challenge has expired", id)
		return
	}
	handler.writeError(writer, veriprov1.ErrChallengeNotFound, "challenge was not found", id)
}

func (handler *Handler) methodNotAllowed(writer http.ResponseWriter, id string) {
	handler.writeError(writer, veriprov1.ErrInvalidField, "method not allowed", id)
}

func (handler *Handler) writeError(writer http.ResponseWriter, code veriprov1.ErrorCode, message, id string) {
	handler.writeJSON(writer, veriprov1.StatusForError(code), veriprov1.ErrorResponse{
		Error: veriprov1.ErrorBody{Code: code, Message: message, RequestID: id},
	})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func jsonContentType(request *http.Request) bool {
	return strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) == "application/json"
}

func requestID(request *http.Request) string {
	if id := request.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "vp-unavailable"
	}
	return "vp-" + hex.EncodeToString(bytes)
}
