package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/verirelay/veriprov/internal/challenge"
)

// maxFileSize bounds every file VeriProv reads its configuration from.
const maxFileSize = 1 << 20

type Config struct {
	Address           string
	LogLevel          slog.Level
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxBodyBytes      int64
	MaxConcurrency    int
	ChallengeTTL      time.Duration
	ChallengeKey      []byte
	IdentityKey       ed25519.PrivateKey
	// Deployments maps the HOST_DATA of each deployment's Bootstrap to its
	// Runtime Config bytes.
	Deployments map[[32]byte][]byte
	Attestation AttestationConfig
}

type AttestationConfig struct {
	Policy []byte
	SEVSNP SEVSNPConfig
}

type SEVSNPConfig struct {
	CheckRevocations    bool
	KDSMaxAttempts      int
	KDSInitialBackoff   time.Duration
	KDSMaxBackoff       time.Duration
	KDSAttemptTimeout   time.Duration
	KDSMaxResponseBytes int64
	KDSCacheDir         string
	KDSCacheMaxEntries  int
	KDSCacheMaxBytes    int64
}

func Load() (Config, error) {
	config := Config{
		Address:           value("VERIPROV_ADDR", ":8080"),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
		MaxBodyBytes:      4 << 20,
		MaxConcurrency:    64,
		ChallengeTTL:      time.Minute,
	}
	if err := config.LogLevel.UnmarshalText([]byte(value("VERIPROV_LOG_LEVEL", "info"))); err != nil {
		return Config{}, errors.New("VERIPROV_LOG_LEVEL must be debug, info, warn, or error")
	}
	var err error
	if config.ReadTimeout, err = duration("VERIPROV_READ_TIMEOUT", config.ReadTimeout); err != nil {
		return Config{}, err
	}
	if config.ReadHeaderTimeout, err = duration("VERIPROV_READ_HEADER_TIMEOUT", config.ReadHeaderTimeout); err != nil {
		return Config{}, err
	}
	if config.WriteTimeout, err = duration("VERIPROV_WRITE_TIMEOUT", config.WriteTimeout); err != nil {
		return Config{}, err
	}
	if config.IdleTimeout, err = duration("VERIPROV_IDLE_TIMEOUT", config.IdleTimeout); err != nil {
		return Config{}, err
	}
	if config.ShutdownTimeout, err = duration("VERIPROV_SHUTDOWN_TIMEOUT", config.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if config.ChallengeTTL, err = duration("VERIPROV_CHALLENGE_TTL", config.ChallengeTTL); err != nil {
		return Config{}, err
	}
	if config.ChallengeTTL%time.Second != 0 {
		return Config{}, errors.New("VERIPROV_CHALLENGE_TTL must be a whole number of seconds")
	}
	if config.MaxBodyBytes, err = integer64("VERIPROV_MAX_BODY_BYTES", config.MaxBodyBytes); err != nil {
		return Config{}, err
	}
	if config.MaxConcurrency, err = integer("VERIPROV_MAX_CONCURRENCY", config.MaxConcurrency); err != nil {
		return Config{}, err
	}
	if config.ChallengeKey, err = requiredFile("VERIPROV_CHALLENGE_KEY_FILE"); err != nil {
		return Config{}, err
	}
	if len(config.ChallengeKey) != challenge.KeySize {
		return Config{}, fmt.Errorf("VERIPROV_CHALLENGE_KEY_FILE must hold exactly %d bytes", challenge.KeySize)
	}
	identityKey, err := requiredFile("VERIPROV_IDENTITY_KEY_FILE")
	if err != nil {
		return Config{}, err
	}
	if config.IdentityKey, err = parseIdentityKey(identityKey); err != nil {
		return Config{}, fmt.Errorf("VERIPROV_IDENTITY_KEY_FILE: %w", err)
	}
	path, ok := os.LookupEnv("VERIPROV_DEPLOYMENTS_FILE")
	if !ok {
		return Config{}, errors.New("VERIPROV_DEPLOYMENTS_FILE is required")
	}
	if config.Deployments, err = loadDeployments(path, config.IdentityKey.Public().(ed25519.PublicKey)); err != nil {
		return Config{}, err
	}
	if config.Attestation, err = loadAttestation(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func loadAttestation() (AttestationConfig, error) {
	policy, err := source("VERIPROV_ATTESTATION_POLICY")
	if err != nil {
		return AttestationConfig{}, err
	}
	if len(policy) == 0 {
		return AttestationConfig{}, errors.New("VERIPROV_ATTESTATION_POLICY or VERIPROV_ATTESTATION_POLICY_FILE is required")
	}
	config := AttestationConfig{Policy: policy}
	if config.SEVSNP, err = loadSEVSNP(); err != nil {
		return AttestationConfig{}, err
	}
	return config, nil
}

func loadSEVSNP() (SEVSNPConfig, error) {
	var config SEVSNPConfig
	var err error
	config.CheckRevocations, err = boolean("VERIPROV_SEVSNP_CHECK_REVOCATIONS", true)
	if err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSMaxAttempts, err = integer("VERIPROV_SEVSNP_KDS_MAX_ATTEMPTS", 4); err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSInitialBackoff, err = duration("VERIPROV_SEVSNP_KDS_INITIAL_BACKOFF", 250*time.Millisecond); err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSMaxBackoff, err = duration("VERIPROV_SEVSNP_KDS_MAX_BACKOFF", 2*time.Second); err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSAttemptTimeout, err = duration("VERIPROV_SEVSNP_KDS_ATTEMPT_TIMEOUT", 10*time.Second); err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSMaxResponseBytes, err = integer64("VERIPROV_SEVSNP_KDS_MAX_RESPONSE_BYTES", 1<<20); err != nil {
		return SEVSNPConfig{}, err
	}
	config.KDSCacheDir = value("VERIPROV_SEVSNP_KDS_CACHE_DIR", "")
	if config.KDSCacheMaxEntries, err = integer("VERIPROV_SEVSNP_KDS_CACHE_MAX_ENTRIES", 256); err != nil {
		return SEVSNPConfig{}, err
	}
	if config.KDSCacheMaxBytes, err = integer64("VERIPROV_SEVSNP_KDS_CACHE_MAX_BYTES", 32<<20); err != nil {
		return SEVSNPConfig{}, err
	}
	return config, nil
}

func value(key, fallback string) string {
	if raw, ok := os.LookupEnv(key); ok {
		return raw
	}
	return fallback
}

func duration(key string, fallback time.Duration) (time.Duration, error) {
	raw := value(key, "")
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func integer(key string, fallback int) (int, error) {
	parsed, err := positiveInteger(key, int64(fallback), strconv.IntSize)
	return int(parsed), err
}

func integer64(key string, fallback int64) (int64, error) {
	return positiveInteger(key, fallback, 64)
}

func positiveInteger(key string, fallback int64, bitSize int) (int64, error) {
	raw := value(key, "")
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(raw, 10, bitSize)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func boolean(key string, fallback bool) (bool, error) {
	raw := value(key, "")
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return parsed, nil
}

// source reads the value of key inline or from the file named by key_FILE.
// It returns nil when neither is set.
func source(key string) ([]byte, error) {
	direct, directOK := os.LookupEnv(key)
	path, pathOK := os.LookupEnv(key + "_FILE")
	if directOK && pathOK {
		return nil, fmt.Errorf("%s and %s must not both be set", key, key+"_FILE")
	}
	if directOK {
		if strings.TrimSpace(direct) == "" {
			return nil, fmt.Errorf("%s must not be empty", key)
		}
		return []byte(direct), nil
	}
	if !pathOK {
		return nil, nil
	}
	return readFile(key+"_FILE", path)
}

// requiredFile reads the file named by the environment variable key.
func requiredFile(key string) ([]byte, error) {
	path, ok := os.LookupEnv(key)
	if !ok {
		return nil, fmt.Errorf("%s is required", key)
	}
	return readFile(key, path)
}

// readFile reads path, which must name a regular file of at most maxFileSize
// bytes that is not blank. name identifies the file in errors.
func readFile(name, path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must name a regular file", name)
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("%s exceeds 1 MiB", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("%s must not be empty", name)
	}
	return data, nil
}
