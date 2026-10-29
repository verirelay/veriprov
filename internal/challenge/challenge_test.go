package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/verirelay/protocol/veriprov1"
)

var testNow = time.Date(2026, 7, 29, 0, 0, 0, 500, time.UTC)

func testIssuer(t *testing.T, key byte) *Issuer {
	t.Helper()
	issuer, err := NewIssuer(bytes.Repeat([]byte{key}, KeySize), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func TestIssueLayout(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	issuer, err := NewIssuer(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	item, err := issuer.Issue(testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !item.IssuedAt.Equal(testNow.Truncate(time.Second)) || !item.ExpiresAt.Equal(item.IssuedAt.Add(time.Minute)) {
		t.Fatalf("issued_at %v, expires_at %v", item.IssuedAt, item.ExpiresAt)
	}
	if len(item.ID) < veriprov1.MinimumChallengeIDSize || len(item.Nonce) != veriprov1.NonceSize {
		t.Fatalf("invalid challenge: %+v", item)
	}
	expiry := binary.BigEndian.AppendUint64(nil, uint64(item.ExpiresAt.Unix()))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("veriprov/1\x00challenge\x00"))
	mac.Write(item.Nonce)
	mac.Write(expiry)
	want := append(append(bytes.Clone(item.Nonce), expiry...), mac.Sum(nil)[:16]...)
	if !bytes.Equal(item.ID, want) {
		t.Fatalf("id = %x, want %x", item.ID, want)
	}
}

func TestVerifyAcceptsTokenRepeatedlyAndAcrossIssuers(t *testing.T) {
	item, err := testIssuer(t, 1).Issue(testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []*Issuer{testIssuer(t, 1), testIssuer(t, 1)} {
		nonce, err := issuer.Verify(item.ID, item.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce, item.Nonce) {
			t.Fatalf("nonce = %x, want %x", nonce, item.Nonce)
		}
	}
}

func TestVerifyRejectsForeignAndTamperedTokens(t *testing.T) {
	issuer := testIssuer(t, 1)
	item, err := issuer.Issue(testNow)
	if err != nil {
		t.Fatal(err)
	}
	tampered := func(index int) []byte {
		id := bytes.Clone(item.ID)
		id[index] ^= 1
		return id
	}
	cases := map[string]struct {
		issuer *Issuer
		id     []byte
	}{
		"other key":       {testIssuer(t, 2), item.ID},
		"tampered nonce":  {issuer, tampered(0)},
		"tampered expiry": {issuer, tampered(veriprov1.NonceSize + expirySize - 1)},
		"tampered tag":    {issuer, tampered(len(item.ID) - 1)},
		"short":           {issuer, item.ID[:len(item.ID)-1]},
		"long":            {issuer, append(bytes.Clone(item.ID), 0)},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := test.issuer.Verify(test.id, item.IssuedAt); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestVerifyExpiresAtExpiry(t *testing.T) {
	issuer := testIssuer(t, 1)
	item, err := issuer.Issue(testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Verify(item.ID, item.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	if _, err := issuer.Verify(item.ID, item.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v, want ErrExpired", err)
	}
}

func TestNewIssuerRejectsInvalidSettings(t *testing.T) {
	cases := map[string]struct {
		key []byte
		ttl time.Duration
	}{
		"short key":          {make([]byte, KeySize-1), time.Minute},
		"zero ttl":           {make([]byte, KeySize), 0},
		"sub-second ttl":     {make([]byte, KeySize), 500 * time.Millisecond},
		"fractional seconds": {make([]byte, KeySize), 1500 * time.Millisecond},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewIssuer(test.key, test.ttl); err == nil {
				t.Fatal("accepted invalid settings")
			}
		})
	}
}
