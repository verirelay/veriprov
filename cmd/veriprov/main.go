package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/verirelay/protocol/veriprov1"
	"github.com/verirelay/veriprov/internal/attestation/sevsnp"
	"github.com/verirelay/veriprov/internal/challenge"
	"github.com/verirelay/veriprov/internal/config"
	"github.com/verirelay/veriprov/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	verifier, err := newVerifier(cfg.Attestation, cfg.MaxConcurrency, logger)
	if err != nil {
		logger.Error("create attestation verifier", "error", err)
		os.Exit(1)
	}
	challenges, err := challenge.NewIssuer(cfg.ChallengeKey, cfg.ChallengeTTL)
	if err != nil {
		logger.Error("create challenge issuer", "error", err)
		os.Exit(1)
	}
	handler, err := server.NewHandler(server.Options{
		Challenges:     challenges,
		Verifier:       verifier,
		IdentityKey:    cfg.IdentityKey,
		Deployments:    cfg.Deployments,
		MaxBodyBytes:   cfg.MaxBodyBytes,
		MaxConcurrency: cfg.MaxConcurrency,
		Logger:         logger,
	})
	if err != nil {
		logger.Error("create server", "error", err)
		os.Exit(1)
	}
	hostData := make([]string, 0, len(cfg.Deployments))
	for value := range cfg.Deployments {
		hostData = append(hostData, hex.EncodeToString(value[:]))
	}
	slices.Sort(hostData)
	logger.Info(
		"deployments loaded",
		"identity_public_key", veriprov1.EncodeBase64URL(cfg.IdentityKey.Public().(ed25519.PublicKey)),
		"host_data", hostData,
	)
	httpServer := &http.Server{Addr: cfg.Address, Handler: handler, ReadTimeout: cfg.ReadTimeout, ReadHeaderTimeout: cfg.ReadHeaderTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout}
	go func() {
		logger.Info("veriprov listening", "address", cfg.Address)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", "error", err)
	}
}

// newVerifier allows maxConcurrency AMD KDS fetches at once, the bound the
// server's concurrency limit puts on the requests that start them.
func newVerifier(cfg config.AttestationConfig, maxConcurrency int, logger *slog.Logger) (*sevsnp.Verifier, error) {
	policy, err := sevsnp.DecodePolicy(cfg.Policy)
	if err != nil {
		return nil, err
	}
	getter, err := sevsnp.NewKDSGetter(sevsnp.KDSGetterOptions{
		MaxAttempts:     cfg.SEVSNP.KDSMaxAttempts,
		InitialBackoff:  cfg.SEVSNP.KDSInitialBackoff,
		MaxBackoff:      cfg.SEVSNP.KDSMaxBackoff,
		AttemptTimeout:  cfg.SEVSNP.KDSAttemptTimeout,
		MaxResponseSize: cfg.SEVSNP.KDSMaxResponseBytes,
		CacheDir:        cfg.SEVSNP.KDSCacheDir,
		CacheMaxEntries: cfg.SEVSNP.KDSCacheMaxEntries,
		CacheMaxBytes:   cfg.SEVSNP.KDSCacheMaxBytes,
		MaxInflight:     maxConcurrency,
	})
	if err != nil {
		return nil, err
	}
	verifier, err := sevsnp.NewVerifier(sevsnp.VerifierOptions{
		Policy:           policy,
		Getter:           getter,
		CheckRevocations: cfg.SEVSNP.CheckRevocations,
	})
	if err != nil {
		return nil, err
	}
	logger.Info(
		"attestation verifier configured",
		"revocation_check", cfg.SEVSNP.CheckRevocations,
		"kds_cache", cfg.SEVSNP.KDSCacheDir != "",
		"allowed_measurements", len(policy.AllowedMeasurements),
	)
	if !cfg.SEVSNP.CheckRevocations {
		logger.Warn("SEV-SNP revocation checking is disabled")
	}
	return verifier, nil
}
