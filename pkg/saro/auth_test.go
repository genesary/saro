package saro

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

func TestKeychainFromConfig(t *testing.T) {
	// Create a temp docker config
	dir := t.TempDir()
	config := map[string]interface{}{
		"auths": map[string]interface{}{
			"registry.example.com": map[string]string{
				"auth": "dGVzdDp0ZXN0", // base64("test:test")
			},
		},
	}
	data, _ := json.Marshal(config)
	configPath := filepath.Join(dir, "config.json")
	os.WriteFile(configPath, data, 0600)

	kc := KeychainFromConfig(configPath)
	if kc == nil {
		t.Fatal("nil keychain")
	}
}

func TestRemoteAuthOption_Explicit(t *testing.T) {
	auth := &authn.Basic{Username: "user", Password: "pass"}
	opt, err := RemoteAuthOption(nil, auth)
	if err != nil {
		t.Fatal(err)
	}
	if opt == nil {
		t.Fatal("nil option")
	}
}

func TestRemoteAuthOption_Keychain(t *testing.T) {
	// Use a fake resource that won't match any keychain
	resource := fakeResource("notareal.registry.example.com")
	opt, err := RemoteAuthOption(resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opt == nil {
		t.Fatal("nil option")
	}
}

func TestFileExists(t *testing.T) {
	if !fileExists("/dev/null") {
		t.Error("/dev/null should exist")
	}
	if fileExists("/nonexistent/path/xyz") {
		t.Error("nonexistent path should not exist")
	}
}

func TestBuildKeychain(t *testing.T) {
	kc := buildKeychain()
	if kc == nil {
		t.Fatal("nil keychain")
	}
}

type fakeResource string

func (f fakeResource) String() string      { return string(f) }
func (f fakeResource) RegistryStr() string  { return string(f) }
