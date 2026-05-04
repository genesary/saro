package saro

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	defaultFulcioURL = "https://fulcio.sigstore.dev"
	defaultRekorURL  = "https://rekor.sigstore.dev"
)

// KeylessSignOptions configures keyless (Fulcio/OIDC) signing.
type KeylessSignOptions struct {
	// OIDC identity token. If empty, reads from COSIGN_IDENTITY_TOKEN env.
	// For CI (GitHub Actions, GitLab CI), the CI provides this automatically.
	IdentityToken string

	// Fulcio server URL. Defaults to https://fulcio.sigstore.dev.
	FulcioURL string

	// Rekor transparency log URL. Defaults to https://rekor.sigstore.dev.
	RekorURL string

	// If true, skip Rekor transparency log upload.
	SkipTlog bool

	// Registry auth for pushing the signature. If nil, uses DefaultKeychain.
	Auth authn.Authenticator

	// Allow HTTP registries.
	Insecure bool
}

// SignKeyless signs an artifact using keyless signing (Fulcio + ephemeral key).
// Requires an OIDC identity token (from CI or COSIGN_IDENTITY_TOKEN env).
func SignKeyless(ctx context.Context, imageRef string, opts KeylessSignOptions) error {
	ref, err := name.NewDigest(imageRef)
	if err != nil {
		return fmt.Errorf("saro: invalid image ref: %w", err)
	}

	// Get OIDC token
	token := opts.IdentityToken
	if token == "" {
		token = os.Getenv("COSIGN_IDENTITY_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("saro: no identity token provided (set COSIGN_IDENTITY_TOKEN or pass IdentityToken)")
	}

	// Generate ephemeral ECDSA P-256 keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("saro: generating ephemeral key: %w", err)
	}

	// Get signing certificate from Fulcio
	fulcioURL := opts.FulcioURL
	if fulcioURL == "" {
		fulcioURL = defaultFulcioURL
	}

	certPEM, chainPEM, err := requestFulcioCert(ctx, fulcioURL, privKey, token)
	if err != nil {
		return fmt.Errorf("saro: fulcio: %w", err)
	}

	// Build cosign payload
	payload, err := cosignPayload(ref)
	if err != nil {
		return fmt.Errorf("saro: payload: %w", err)
	}

	// Sign with ephemeral key
	payloadHash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, payloadHash[:])
	if err != nil {
		return fmt.Errorf("saro: signing: %w", err)
	}

	// Upload to Rekor (transparency log)
	var rekorBundle []byte
	if !opts.SkipTlog {
		rekorURL := opts.RekorURL
		if rekorURL == "" {
			rekorURL = defaultRekorURL
		}
		rekorBundle, err = uploadToRekor(ctx, rekorURL, payload, sig, certPEM)
		if err != nil {
			return fmt.Errorf("saro: rekor: %w", err)
		}
	}

	// Push signature to registry
	return pushKeylessSignature(ctx, ref, payload, sig, certPEM, chainPEM, rekorBundle, opts)
}

// requestFulcioCert exchanges an OIDC token + public key for a short-lived signing cert.
func requestFulcioCert(ctx context.Context, fulcioURL string, privKey *ecdsa.PrivateKey, oidcToken string) (certPEM, chainPEM []byte, err error) {
	// Marshal public key to DER
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling public key: %w", err)
	}

	// Sign the OIDC token subject as proof of possession
	emailHash := sha256.Sum256([]byte("unused"))
	proofSig, err := ecdsa.SignASN1(rand.Reader, privKey, emailHash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("proof of possession: %w", err)
	}

	reqBody := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"content":   base64.StdEncoding.EncodeToString(pubDER),
			"algorithm": "ecdsa",
		},
		"signedEmailAddress": base64.StdEncoding.EncodeToString(proofSig),
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fulcioURL+"/api/v1/signingCert", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+oidcToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/pem-certificate-chain")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse PEM certificate chain: first cert is the signing cert, rest is the chain
	var certs [][]byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certs = append(certs, pem.EncodeToMemory(block))
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates in response")
	}

	certPEM = certs[0]
	if len(certs) > 1 {
		for _, c := range certs[1:] {
			chainPEM = append(chainPEM, c...)
		}
	}

	return certPEM, chainPEM, nil
}

// uploadToRekor uploads a signature entry to the Rekor transparency log.
func uploadToRekor(ctx context.Context, rekorURL string, payload, sig, certPEM []byte) ([]byte, error) {
	// Rekor hashedrekord entry
	payloadHash := sha256.Sum256(payload)

	entry := map[string]interface{}{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]interface{}{
			"signature": map[string]interface{}{
				"content":   base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]string{"content": base64.StdEncoding.EncodeToString(certPEM)},
			},
			"data": map[string]interface{}{
				"hash": map[string]string{
					"algorithm": "sha256",
					"value":     fmt.Sprintf("%x", payloadHash),
				},
			},
		},
	}

	bodyJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rekorURL+"/api/v1/log/entries", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Return the rekor bundle (the full response) for embedding in signature annotations
	return body, nil
}

func pushKeylessSignature(ctx context.Context, digest name.Digest, payload, sig, certPEM, chainPEM, rekorBundle []byte, opts KeylessSignOptions) error {
	// Cosign signature tag: sha256-<hex>.sig
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		return err
	}
	sigTag := digest.Context().Tag(fmt.Sprintf("%s-%s.sig", h.Algorithm, h.Hex))

	nameOpts := []name.Option{}
	if opts.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	sigRef, err := name.ParseReference(sigTag.String(), nameOpts...)
	if err != nil {
		return fmt.Errorf("saro: sig ref: %w", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Build layer annotations (cosign format)
	layerAnnotations := map[string]string{
		"dev.cosignproject.cosign/signature": sigB64,
		"dev.sigstore.cosign/certificate":    base64.StdEncoding.EncodeToString(certPEM),
		"dev.sigstore.cosign/chain":          base64.StdEncoding.EncodeToString(chainPEM),
	}
	if rekorBundle != nil {
		layerAnnotations["dev.sigstore.cosign/bundle"] = string(rekorBundle)
	}

	// Build signature image
	layer := static.NewLayer(payload, types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json"))
	adds := mutate.Addendum{
		Layer:       layer,
		Annotations: layerAnnotations,
	}
	img, err := mutate.Append(empty.Image, adds)
	if err != nil {
		return fmt.Errorf("saro: building sig image: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	// Auth
	auth := opts.Auth
	if auth == nil {
		auth, err = Keychain.Resolve(sigRef.(name.Tag).Context())
		if err != nil {
			return fmt.Errorf("saro: resolving auth: %w", err)
		}
	}

	remoteOpts := []remote.Option{
		remote.WithAuth(auth),
		remote.WithContext(ctx),
	}

	return remote.Write(sigRef, img, remoteOpts...)
}
