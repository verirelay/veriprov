package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/verirelay/protocol/guest"
	"github.com/verirelay/protocol/veriprov1"
	"github.com/verirelay/veriprov/internal/strictjson"
)

// deployment is one entry of the deployments file. Relative paths are relative
// to the directory of the deployments file.
type deployment struct {
	BootstrapFile     string `json:"bootstrap_file"`
	RuntimeConfigFile string `json:"runtime_config_file"`
}

// loadDeployments reads the deployments file at path and returns each
// deployment's Runtime Config keyed by the HOST_DATA of its Bootstrap. Every
// Bootstrap must name identity as its identity_public_key, and no two
// deployments may share a Bootstrap.
func loadDeployments(path string, identity ed25519.PublicKey) (map[[32]byte][]byte, error) {
	data, err := readFile("VERIPROV_DEPLOYMENTS_FILE", path)
	if err != nil {
		return nil, err
	}
	var entries []deployment
	if err := strictjson.Decode(data, &entries); err != nil {
		return nil, fmt.Errorf("decode VERIPROV_DEPLOYMENTS_FILE: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("VERIPROV_DEPLOYMENTS_FILE must list at least one deployment")
	}
	resolve := func(file string) string {
		if filepath.IsAbs(file) {
			return file
		}
		return filepath.Join(filepath.Dir(path), file)
	}
	deployments := make(map[[32]byte][]byte, len(entries))
	for i, entry := range entries {
		name := fmt.Sprintf("deployment %d", i)
		if entry.BootstrapFile == "" || entry.RuntimeConfigFile == "" {
			return nil, fmt.Errorf("%s: bootstrap_file and runtime_config_file are required", name)
		}
		hostData, err := loadBootstrap(resolve(entry.BootstrapFile), identity)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if _, duplicate := deployments[hostData]; duplicate {
			return nil, fmt.Errorf("%s: bootstrap_file repeats the Bootstrap of an earlier deployment (HOST_DATA %s)", name, hex.EncodeToString(hostData[:]))
		}
		runtimeConfig, err := loadRuntimeConfig(resolve(entry.RuntimeConfigFile))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		deployments[hostData] = runtimeConfig
	}
	return deployments, nil
}

func loadBootstrap(path string, identity ed25519.PublicKey) ([32]byte, error) {
	data, err := readFile("bootstrap_file", path)
	if err != nil {
		return [32]byte{}, err
	}
	bootstrap, err := guest.DecodeBootstrap(data)
	if err != nil {
		return [32]byte{}, fmt.Errorf("bootstrap_file: %w", err)
	}
	if err := bootstrap.Validate(); err != nil {
		return [32]byte{}, fmt.Errorf("bootstrap_file: %w", err)
	}
	key, err := bootstrap.IdentityKey()
	if err != nil {
		return [32]byte{}, fmt.Errorf("bootstrap_file: %w", err)
	}
	if !key.Equal(identity) {
		return [32]byte{}, fmt.Errorf("bootstrap_file: identity_public_key is not the public key of VERIPROV_IDENTITY_KEY_FILE, %s", veriprov1.EncodeBase64URL(identity))
	}
	return guest.HostData(data), nil
}

func loadRuntimeConfig(path string) ([]byte, error) {
	data, err := readFile("runtime_config_file", path)
	if err != nil {
		return nil, err
	}
	var runtimeConfig veriprov1.RuntimeConfigV1
	if err := veriprov1.DecodeJSON(data, &runtimeConfig); err != nil {
		return nil, fmt.Errorf("decode runtime_config_file: %w", err)
	}
	if err := runtimeConfig.Validate(); err != nil {
		return nil, fmt.Errorf("runtime_config_file: %w", err)
	}
	return data, nil
}
