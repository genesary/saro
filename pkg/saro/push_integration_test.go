//go:build integration

package saro

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

func getTestAuth(t *testing.T) authn.Authenticator {
	user := os.Getenv("CURLOCI_TEST_USER")
	pass := os.Getenv("CURLOCI_TEST_PASSWORD")
	if user == "" || pass == "" {
		t.Skip("CURLOCI_TEST_USER and CURLOCI_TEST_PASSWORD not set")
	}
	return &authn.Basic{Username: user, Password: pass}
}

func getTestRegistry(t *testing.T) string {
	reg := os.Getenv("CURLOCI_TEST_REGISTRY")
	if reg == "" {
		t.Skip("CURLOCI_TEST_REGISTRY not set")
	}
	return reg
}

func TestPush_Integration(t *testing.T) {
	auth := getTestAuth(t)
	registry := getTestRegistry(t)

	result, err := Push(context.Background(), PushOptions{
		SourceURL:   "https://raw.githubusercontent.com/google/go-containerregistry/main/LICENSE",
		Destination: registry + "/saro-test/license:latest",
		Auth:        auth,
	})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	if result.Size == 0 {
		t.Error("expected non-zero size")
	}
	if result.Digest.Algorithm != "sha256" {
		t.Errorf("unexpected digest algorithm: %s", result.Digest.Algorithm)
	}
	t.Logf("Pushed: %s (%d bytes)", result.Digest, result.Size)
}

func TestPush_ChecksumVerification(t *testing.T) {
	auth := getTestAuth(t)
	registry := getTestRegistry(t)

	_, err := Push(context.Background(), PushOptions{
		SourceURL:      "https://raw.githubusercontent.com/google/go-containerregistry/main/LICENSE",
		Destination:    registry + "/saro-test/license-bad:latest",
		Auth:           auth,
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("expected checksum error")
	}
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("expected ErrChecksumMismatch, got: %v", err)
	}
}
