package saro

import (
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Keychain returns a multi-keychain that checks credentials from all common
// container runtime config locations, in order:
//
//  1. $DOCKER_CONFIG/config.json (explicit override)
//  2. ~/.docker/config.json (Docker default)
//  3. $XDG_RUNTIME_DIR/containers/auth.json (Podman default)
//  4. ~/.config/containers/auth.json (Podman rootless fallback)
//  5. Credential helpers (docker-credential-*, configured in any of the above)
//
// The first keychain that returns a non-anonymous credential wins.
var Keychain authn.Keychain = buildKeychain()

func buildKeychain() authn.Keychain {
	keychains := []authn.Keychain{
		authn.DefaultKeychain, // Docker: ~/.docker/config.json + $DOCKER_CONFIG
	}

	// Podman: $XDG_RUNTIME_DIR/containers/auth.json
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		podmanPath := filepath.Join(xdg, "containers")
		if fileExists(filepath.Join(podmanPath, "auth.json")) {
			keychains = append(keychains, &dockerConfigKeychain{dir: podmanPath})
		}
	}

	// Podman rootless fallback: ~/.config/containers/auth.json
	if home, err := os.UserHomeDir(); err == nil {
		podmanConfig := filepath.Join(home, ".config", "containers")
		if fileExists(filepath.Join(podmanConfig, "auth.json")) {
			keychains = append(keychains, &dockerConfigKeychain{dir: podmanConfig})
		}
	}

	return authn.NewMultiKeychain(keychains...)
}

// dockerConfigKeychain reads auth from a specific directory containing
// config.json or auth.json (Podman-compatible).
type dockerConfigKeychain struct {
	dir string
}

func (k *dockerConfigKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	// Temporarily set DOCKER_CONFIG to the podman path, resolve, then restore.
	// go-containerregistry's config.Load respects DOCKER_CONFIG.
	orig := os.Getenv("DOCKER_CONFIG")
	os.Setenv("DOCKER_CONFIG", k.dir)
	defer func() {
		if orig != "" {
			os.Setenv("DOCKER_CONFIG", orig)
		} else {
			os.Unsetenv("DOCKER_CONFIG")
		}
	}()

	// Symlink or copy auth.json → config.json if needed
	authJSON := filepath.Join(k.dir, "auth.json")
	configJSON := filepath.Join(k.dir, "config.json")
	if fileExists(authJSON) && !fileExists(configJSON) {
		// Podman's auth.json is Docker config.json compatible
		// Read it through the default keychain by temporarily symlinking
		data, err := os.ReadFile(authJSON)
		if err != nil {
			return authn.Anonymous, nil
		}
		// Write a temporary config.json
		if err := os.WriteFile(configJSON, data, 0600); err != nil {
			return authn.Anonymous, nil
		}
		defer os.Remove(configJSON)
	}

	return authn.DefaultKeychain.Resolve(target)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// KeychainFromConfig returns a keychain that reads credentials from the given
// Docker/Podman JSON config file path. The file can be either a Docker
// config.json or a Podman auth.json (same format).
func KeychainFromConfig(configPath string) authn.Keychain {
	dir := filepath.Dir(configPath)
	return authn.NewMultiKeychain(&dockerConfigKeychain{dir: dir}, Keychain)
}

// RemoteAuthOption returns a remote.Option configured with the multi-keychain.
func RemoteAuthOption(target authn.Resource, explicit authn.Authenticator) (remote.Option, error) {
	if explicit != nil {
		return remote.WithAuth(explicit), nil
	}
	auth, err := Keychain.Resolve(target)
	if err != nil {
		return nil, err
	}
	return remote.WithAuth(auth), nil
}
