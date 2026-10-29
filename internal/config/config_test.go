package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verirelay/protocol/veriprov1"
)

const (
	testPolicy        = `{"allowed_measurements":["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]}`
	testRuntimeConfig = `{"version":"verirelay-runtime-config/1","admin_token":"test-only-admin-token","future_field":true}`
)

type testEnv struct {
	dir      string
	identity ed25519.PrivateKey
}

func (env testEnv) write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(env.dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (env testEnv) bootstrap(key ed25519.PublicKey, profile string) []byte {
	return []byte(`{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"` + veriprov1.EncodeBase64URL(key) + `","profile":"` + profile + `"}`)
}

// setupEnv writes a valid configuration to a temporary directory and points
// the VERIPROV_* variables at it.
func setupEnv(t *testing.T) testEnv {
	t.Helper()
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv{dir: t.TempDir(), identity: identity}
	t.Setenv("VERIPROV_IDENTITY_KEY_FILE", env.write(t, "identity-key.pem", identityPEM(t, identity)))
	t.Setenv("VERIPROV_CHALLENGE_KEY_FILE", env.write(t, "challenge-key", bytes.Repeat([]byte{1}, 32)))
	env.write(t, "bootstrap.json", env.bootstrap(identity.Public().(ed25519.PublicKey), "a"))
	env.write(t, "runtime-config.json", []byte(testRuntimeConfig))
	t.Setenv("VERIPROV_DEPLOYMENTS_FILE", env.write(t, "deployments.json", []byte(`[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]`)))
	t.Setenv("VERIPROV_ATTESTATION_POLICY", testPolicy)
	return env
}

func identityPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestLoadDeployments(t *testing.T) {
	env := setupEnv(t)
	other := env.write(t, "other-bootstrap.json", env.bootstrap(env.identity.Public().(ed25519.PublicKey), "b"))
	env.write(t, "deployments.json", []byte(`[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"},{"bootstrap_file":"`+other+`","runtime_config_file":"runtime-config.json"}]`))
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !config.IdentityKey.Equal(env.identity) {
		t.Fatal("identity key mismatch")
	}
	if !bytes.Equal(config.ChallengeKey, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("challenge key mismatch")
	}
	if len(config.Deployments) != 2 {
		t.Fatalf("deployments = %d, want 2", len(config.Deployments))
	}
	for _, name := range []string{"bootstrap.json", "other-bootstrap.json"} {
		data, err := os.ReadFile(filepath.Join(env.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := config.Deployments[sha256.Sum256(data)]; string(got) != testRuntimeConfig {
			t.Fatalf("runtime config for %s = %q", name, got)
		}
	}
	if !config.Attestation.SEVSNP.CheckRevocations || config.Attestation.SEVSNP.KDSCacheMaxEntries <= 0 || config.Attestation.SEVSNP.KDSCacheMaxBytes <= 0 {
		t.Fatalf("SEV-SNP defaults = %+v", config.Attestation.SEVSNP)
	}
}

func TestLoadRequiresFiles(t *testing.T) {
	for _, key := range []string{"VERIPROV_IDENTITY_KEY_FILE", "VERIPROV_CHALLENGE_KEY_FILE", "VERIPROV_DEPLOYMENTS_FILE", "VERIPROV_ATTESTATION_POLICY"} {
		t.Run(key, func(t *testing.T) {
			setupEnv(t)
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("accepted configuration without %s", key)
			}
		})
	}
}

func TestLoadRejectsInvalidKeys(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		file string
		key  string
		data func(*testing.T) []byte
	}{
		{"short challenge key", "challenge-key", "VERIPROV_CHALLENGE_KEY_FILE", func(*testing.T) []byte { return bytes.Repeat([]byte{1}, 31) }},
		{"long challenge key", "challenge-key", "VERIPROV_CHALLENGE_KEY_FILE", func(*testing.T) []byte { return bytes.Repeat([]byte{1}, 33) }},
		{"identity key not PEM", "identity-key.pem", "VERIPROV_IDENTITY_KEY_FILE", func(*testing.T) []byte { return bytes.Repeat([]byte{1}, 32) }},
		{"identity key not Ed25519", "identity-key.pem", "VERIPROV_IDENTITY_KEY_FILE", func(t *testing.T) []byte { return identityPEM(t, x25519) }},
		{"identity key trailing data", "identity-key.pem", "VERIPROV_IDENTITY_KEY_FILE", func(t *testing.T) []byte {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return append(identityPEM(t, key), identityPEM(t, key)...)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := setupEnv(t)
			env.write(t, test.file, test.data(t))
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want an error naming %s", err, test.key)
			}
		})
	}
}

func TestLoadRejectsInvalidDeployments(t *testing.T) {
	_, otherIdentity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"empty list", map[string]string{"deployments.json": `[]`}, "at least one deployment"},
		{"not a list", map[string]string{"deployments.json": `{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}`}, "decode VERIPROV_DEPLOYMENTS_FILE"},
		{"unknown field", map[string]string{"deployments.json": `[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json","profile":"a"}]`}, "unknown field"},
		{"duplicate key", map[string]string{"deployments.json": `[{"bootstrap_file":"bootstrap.json","bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]`}, "duplicate JSON key"},
		{"missing runtime config field", map[string]string{"deployments.json": `[{"bootstrap_file":"bootstrap.json"}]`}, "are required"},
		{"missing bootstrap file", map[string]string{"deployments.json": `[{"bootstrap_file":"missing.json","runtime_config_file":"runtime-config.json"}]`}, "read bootstrap_file"},
		{"repeated bootstrap", map[string]string{"deployments.json": `[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"},{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]`}, "deployment 1: bootstrap_file repeats"},
		{"bootstrap unknown field", map[string]string{"bootstrap.json": `{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","tls_spki_sha256":"x"}`}, "unknown JSON field"},
		{"bootstrap invalid url", map[string]string{"bootstrap.json": `{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"http://veriprov.example.com","identity_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`}, "HTTPS origin"},
		{"bootstrap other identity", map[string]string{"bootstrap.json": string(testEnv{}.bootstrap(otherIdentity.Public().(ed25519.PublicKey), "a"))}, "identity_public_key is not the public key"},
		{"runtime config without version", map[string]string{"runtime-config.json": `{"admin_token":"test-only-admin-token"}`}, "runtime_config_file: version"},
		{"runtime config duplicate key", map[string]string{"runtime-config.json": `{"version":"verirelay-runtime-config/1","admin_token":"a","admin_token":"b"}`}, "duplicate JSON key"},
		{"runtime config not JSON", map[string]string{"runtime-config.json": `admin_token=a`}, "decode runtime_config_file"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := setupEnv(t)
			for name, data := range test.files {
				env.write(t, name, []byte(data))
			}
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want an error containing %q", err, test.want)
			}
		})
	}
}

func TestReadFileRejectsUnsafeSources(t *testing.T) {
	cases := []struct {
		name string
		path func(*testing.T) string
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }},
		{"directory", func(t *testing.T) string { return t.TempDir() }},
		{"blank", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "blank")
			if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"oversized", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "large")
			if err := os.WriteFile(path, []byte(strings.Repeat("x", maxFileSize+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readFile("test", test.path(t)); err == nil {
				t.Fatal("accepted unsafe source")
			}
		})
	}
}

func TestLoadRejectsInvalidSettings(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"invalid log level", "VERIPROV_LOG_LEVEL", "verbose"},
		{"zero ttl", "VERIPROV_CHALLENGE_TTL", "0s"},
		{"fractional ttl", "VERIPROV_CHALLENGE_TTL", "1500ms"},
		{"invalid duration", "VERIPROV_CHALLENGE_TTL", "later"},
		{"zero concurrency", "VERIPROV_MAX_CONCURRENCY", "0"},
		{"invalid body size", "VERIPROV_MAX_BODY_BYTES", "many"},
		{"invalid revocation boolean", "VERIPROV_SEVSNP_CHECK_REVOCATIONS", "not-bool"},
		{"blank policy", "VERIPROV_ATTESTATION_POLICY", " \n "},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			setupEnv(t)
			t.Setenv(test.key, test.value)
			if _, err := Load(); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestLoadRejectsConflictingAttestationPolicySources(t *testing.T) {
	env := setupEnv(t)
	t.Setenv("VERIPROV_ATTESTATION_POLICY_FILE", env.write(t, "policy.json", []byte(testPolicy)))
	if _, err := Load(); err == nil {
		t.Fatal("accepted conflicting policy sources")
	}
}

func TestLoadAttestationPolicyFromFile(t *testing.T) {
	env := setupEnv(t)
	if err := os.Unsetenv("VERIPROV_ATTESTATION_POLICY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERIPROV_ATTESTATION_POLICY_FILE", env.write(t, "policy.json", []byte(testPolicy)))
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(config.Attestation.Policy) != testPolicy {
		t.Fatalf("policy = %q", config.Attestation.Policy)
	}
}
