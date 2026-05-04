package saro

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestCosignPayload(t *testing.T) {
	ref, err := newTestDigest("registry.io/repo@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1")
	if err != nil {
		t.Fatal(err)
	}

	payload, err := cosignPayload(ref)
	if err != nil {
		t.Fatal(err)
	}

	if len(payload) == 0 {
		t.Fatal("empty payload")
	}

	// Should contain the digest
	if !contains(payload, "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1") {
		t.Error("payload missing digest")
	}
	// Should contain the repo
	if !contains(payload, "registry.io/repo") {
		t.Error("payload missing docker-reference")
	}
	// Should contain cosign type
	if !contains(payload, "cosign container image signature") {
		t.Error("payload missing type")
	}
}

func TestSignerFromKey_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := signerFromKey(key)
	if err != nil {
		t.Fatalf("ECDSA: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestSignerFromKey_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, err := signerFromKey(key)
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestSignerFromKey_ED25519(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := signerFromKey(key)
	if err != nil {
		t.Fatalf("ED25519: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestSign_BadRef(t *testing.T) {
	err := Sign(context.Background(), "not-a-digest", SignOptions{KeyPath: "/tmp/nonexistent.key"})
	if err == nil {
		t.Fatal("expected error for bad ref")
	}
}

func TestSign_BadKeyPath(t *testing.T) {
	err := Sign(context.Background(),
		"localhost:5000/repo@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
		SignOptions{KeyPath: "/tmp/nonexistent_key_file.pem"},
	)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestSign_WithTempKey(t *testing.T) {
	// Generate an unencrypted ECDSA key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	keyFile := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	err := Sign(context.Background(),
		"localhost:5000/repo@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
		SignOptions{KeyPath: keyFile, Insecure: true},
	)
	// Should fail at registry push, not at key loading or signing
	if err == nil {
		t.Fatal("expected error (no registry)")
	}
	if contains([]byte(err.Error()), "reading key") || contains([]byte(err.Error()), "parsing key") || contains([]byte(err.Error()), "signing") {
		t.Errorf("failed at wrong step: %v", err)
	}
}

func TestSignerFromKey_Unsupported(t *testing.T) {
	_, err := signerFromKey("not a key")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
		{1536, "1.5 KiB"},
	}
	for _, tt := range tests {
		got := HumanBytes(tt.input)
		if got != tt.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func newTestDigest(ref string) (name.Digest, error) {
	return name.NewDigest(ref)
}

func contains(b []byte, s string) bool {
	return len(b) > 0 && len(s) > 0 && string(b) != "" && indexOf(b, []byte(s)) >= 0
}

func indexOf(b, sub []byte) int {
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
