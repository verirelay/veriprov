// Package challenge issues and verifies stateless veriprov/1 challenges.
package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/verirelay/protocol/veriprov1"
)

// KeySize is the length of the challenge key, in bytes.
const KeySize = 32

const (
	macContext = "veriprov/1\x00challenge\x00"
	expirySize = 8
	tagSize    = 16
	idSize     = veriprov1.NonceSize + expirySize + tagSize
)

var (
	ErrNotFound = errors.New("challenge not found")
	ErrExpired  = errors.New("challenge expired")
)

// Challenge is an issued challenge. ID is the challenge token
// nonce || expires_at || tag, where expires_at is ExpiresAt in big-endian Unix
// seconds and tag is the first 16 bytes of
// HMAC-SHA256(key, "veriprov/1\x00challenge\x00" || nonce || expires_at).
type Challenge struct {
	ID        []byte
	Nonce     []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Issuer issues challenges and verifies their tokens with one key, so every
// Issuer with the same key accepts the same tokens.
type Issuer struct {
	key []byte
	ttl time.Duration
}

// NewIssuer returns an Issuer for a KeySize-byte key whose challenges expire
// after ttl, a positive whole number of seconds.
func NewIssuer(key []byte, ttl time.Duration) (*Issuer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("challenge key is %d bytes, want %d", len(key), KeySize)
	}
	if ttl < time.Second || ttl%time.Second != 0 {
		return nil, errors.New("challenge ttl must be a positive whole number of seconds")
	}
	return &Issuer{key: bytes.Clone(key), ttl: ttl}, nil
}

// Issue returns a new challenge issued at now, truncated to the second.
func (issuer *Issuer) Issue(now time.Time) (Challenge, error) {
	nonce := make([]byte, veriprov1.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}
	issuedAt := now.UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(issuer.ttl)
	seconds := expiresAt.Unix()
	if seconds < 0 {
		return Challenge{}, errors.New("challenge expiry precedes the Unix epoch")
	}
	body := binary.BigEndian.AppendUint64(bytes.Clone(nonce), uint64(seconds))
	return Challenge{
		ID:        append(body, issuer.tag(body)...),
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// Verify returns the nonce of the challenge token id. It returns ErrNotFound
// for a token this Issuer did not issue, and ErrExpired for one that has
// expired at now.
func (issuer *Issuer) Verify(id []byte, now time.Time) ([]byte, error) {
	if len(id) != idSize {
		return nil, ErrNotFound
	}
	body := id[:veriprov1.NonceSize+expirySize]
	seconds := binary.BigEndian.Uint64(body[veriprov1.NonceSize:])
	if seconds > math.MaxInt64 || !hmac.Equal(id[len(body):], issuer.tag(body)) {
		return nil, ErrNotFound
	}
	if expiresAt := time.Unix(int64(seconds), 0); !now.Before(expiresAt) {
		return nil, ErrExpired
	}
	return bytes.Clone(id[:veriprov1.NonceSize]), nil
}

func (issuer *Issuer) tag(body []byte) []byte {
	mac := hmac.New(sha256.New, issuer.key)
	mac.Write([]byte(macContext))
	mac.Write(body)
	return mac.Sum(nil)[:tagSize]
}
