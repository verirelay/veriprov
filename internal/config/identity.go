package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// parseIdentityKey parses an Ed25519 private key in a single PEM "PRIVATE KEY"
// (PKCS #8) block, the form `openssl genpkey -algorithm ed25519` writes.
func parseIdentityKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("must hold exactly one PEM PRIVATE KEY block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS #8 private key: %w", err)
	}
	identity, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want an Ed25519 key", key)
	}
	return identity, nil
}
