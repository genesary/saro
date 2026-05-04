package saro

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestFulcioCert_Success(t *testing.T) {
	// Generate a test CA + leaf cert to return from mock Fulcio
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test@example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * time.Minute),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	// Mock Fulcio server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/signingCert" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content-type")
		}

		w.WriteHeader(http.StatusCreated)
		// Return leaf + CA as PEM chain
		w.Write(leafPEM)
		w.Write(caPEM)
	}))
	defer ts.Close()

	ephKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, chainPEM, err := requestFulcioCert(context.Background(), ts.URL, ephKey, "test-oidc-token")
	if err != nil {
		t.Fatalf("requestFulcioCert failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("empty cert PEM")
	}
	if len(chainPEM) == 0 {
		t.Error("empty chain PEM")
	}

	// Verify the cert is parseable
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if cert.Subject.CommonName != "test@example.com" {
		t.Errorf("CN = %s, want test@example.com", cert.Subject.CommonName)
	}
}

func TestRequestFulcioCert_Unauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer ts.Close()

	ephKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, err := requestFulcioCert(context.Background(), ts.URL, ephKey, "bad-token")
	if err == nil {
		t.Fatal("expected error for unauthorized")
	}
}

func TestRequestFulcioCert_NoCerts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("not a PEM"))
	}))
	defer ts.Close()

	ephKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, err := requestFulcioCert(context.Background(), ts.URL, ephKey, "token")
	if err == nil {
		t.Fatal("expected error for no certs")
	}
}

func TestUploadToRekor_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content-type")
		}

		// Verify the request body is valid JSON
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("invalid request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if body["kind"] != "hashedrekord" {
			t.Errorf("kind = %v, want hashedrekord", body["kind"])
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"logIndex":12345}`))
	}))
	defer ts.Close()

	payload := []byte("test payload")
	sig := []byte("test signature")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	bundle, err := uploadToRekor(context.Background(), ts.URL, payload, sig, certPEM)
	if err != nil {
		t.Fatalf("uploadToRekor failed: %v", err)
	}
	if len(bundle) == 0 {
		t.Error("empty bundle")
	}
}

func TestUploadToRekor_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	_, err := uploadToRekor(context.Background(), ts.URL, []byte("p"), []byte("s"), []byte("c"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignKeyless_NoToken(t *testing.T) {
	// Unset env to ensure no token
	t.Setenv("COSIGN_IDENTITY_TOKEN", "")

	err := SignKeyless(context.Background(), "registry.io/repo@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1", KeylessSignOptions{})
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if !contains([]byte(err.Error()), "no identity token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignKeyless_BadRef(t *testing.T) {
	err := SignKeyless(context.Background(), "not-a-digest-ref", KeylessSignOptions{
		IdentityToken: "token",
	})
	if err == nil {
		t.Fatal("expected error for bad ref")
	}
}

func TestSignKeyless_FullFlow(t *testing.T) {
	// Generate test CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test@example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * time.Minute),
	}

	// Mock Fulcio
	fulcio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the public key from request to create a cert for it
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Generate a leaf cert (with a random key since we can't extract from request easily)
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		w.WriteHeader(http.StatusCreated)
		w.Write(leafPEM)
		w.Write(caPEM)
	}))
	defer fulcio.Close()

	// Mock Rekor
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"logIndex":1}`))
	}))
	defer rekor.Close()

	// SignKeyless will fail at pushKeylessSignature (no real registry) but should
	// succeed through Fulcio + Rekor
	err := SignKeyless(context.Background(),
		"localhost:5000/test/keyless@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
		KeylessSignOptions{
			IdentityToken: "test-token",
			FulcioURL:     fulcio.URL,
			RekorURL:      rekor.URL,
			Insecure:      true,
		},
	)
	// Should fail at registry push, not at Fulcio/Rekor
	if err == nil {
		t.Fatal("expected error (no registry)")
	}
	// Error should be about pushing, not about Fulcio or Rekor
	if contains([]byte(err.Error()), "fulcio") || contains([]byte(err.Error()), "rekor") || contains([]byte(err.Error()), "identity token") {
		t.Errorf("failed at wrong step: %v", err)
	}
}

func TestSignKeyless_SkipTlog(t *testing.T) {
	// Generate test CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * time.Minute),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	fulcio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write(leafPEM)
		w.Write(caPEM)
	}))
	defer fulcio.Close()

	err := SignKeyless(context.Background(),
		"localhost:5000/test/notlog@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
		KeylessSignOptions{
			IdentityToken: "token",
			FulcioURL:     fulcio.URL,
			SkipTlog:      true,
			Insecure:      true,
		},
	)
	// Should skip Rekor entirely and fail at registry push
	if err == nil {
		t.Fatal("expected error (no registry)")
	}
	if contains([]byte(err.Error()), "rekor") {
		t.Errorf("should have skipped rekor: %v", err)
	}
}

func TestRekorPayloadHash(t *testing.T) {
	payload := []byte("test payload")
	hash := sha256.Sum256(payload)
	hex := hashHex(hash[:])
	if len(hex) != 64 {
		t.Errorf("hash hex length = %d, want 64", len(hex))
	}
	// Verify deterministic
	hash2 := sha256.Sum256(payload)
	hex2 := hashHex(hash2[:])
	if hex != hex2 {
		t.Error("hash not deterministic")
	}
}

func hashHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}
