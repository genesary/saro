package saro

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// SignOptions configures artifact signing after push.
type SignOptions struct {
	// Path to a PEM-encoded private key (cosign-compatible PKCS8 or EC key).
	KeyPath string

	// Password for the encrypted key. If empty, tries COSIGN_PASSWORD env.
	KeyPassword string

	// Registry auth for pushing the signature. If nil, uses DefaultKeychain.
	Auth authn.Authenticator

	// Allow HTTP registries for signature push.
	Insecure bool
}

// Sign signs an already-pushed OCI artifact by digest and pushes the signature
// as a cosign-compatible tag (sha256-<hex>.sig).
func Sign(ctx context.Context, imageRef string, opts SignOptions) error {
	ref, err := name.NewDigest(imageRef)
	if err != nil {
		return fmt.Errorf("saro: invalid image ref for signing: %w", err)
	}

	// Resolve key password
	password := []byte(opts.KeyPassword)
	if len(password) == 0 {
		if p := os.Getenv("COSIGN_PASSWORD"); p != "" {
			password = []byte(p)
		}
	}

	keyBytes, err := os.ReadFile(opts.KeyPath)
	if err != nil {
		return fmt.Errorf("saro: reading key: %w", err)
	}

	// Parse private key
	passFunc := func(_ bool) ([]byte, error) { return password, nil }
	privKey, err := cryptoutils.UnmarshalPEMToPrivateKey(keyBytes, passFunc)
	if err != nil {
		return fmt.Errorf("saro: parsing key: %w", err)
	}

	// Create signer from the private key
	signer, err := signerFromKey(privKey)
	if err != nil {
		return fmt.Errorf("saro: creating signer: %w", err)
	}

	// Build cosign simple signing payload
	payload, err := cosignPayload(ref)
	if err != nil {
		return fmt.Errorf("saro: building payload: %w", err)
	}

	// Sign the payload
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("saro: signing: %w", err)
	}

	// Push signature
	return pushCosignSignature(ctx, ref, payload, sig, opts)
}

func signerFromKey(privKey crypto.PrivateKey) (sigsig.Signer, error) {
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		return sigsig.LoadECDSASigner(k, crypto.SHA256)
	case *rsa.PrivateKey:
		return sigsig.LoadRSAPKCS1v15Signer(k, crypto.SHA256)
	case ed25519.PrivateKey:
		return sigsig.LoadED25519Signer(k)
	default:
		return nil, fmt.Errorf("unsupported key type %T", privKey)
	}
}

func cosignPayload(digest name.Digest) ([]byte, error) {
	payload := map[string]interface{}{
		"critical": map[string]interface{}{
			"identity": map[string]string{
				"docker-reference": digest.Context().String(),
			},
			"image": map[string]string{
				"docker-manifest-digest": digest.DigestStr(),
			},
			"type": "cosign container image signature",
		},
		"optional": map[string]interface{}{},
	}
	return json.Marshal(payload)
}

func pushCosignSignature(ctx context.Context, digest name.Digest, payload, sig []byte, opts SignOptions) error {
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
		return fmt.Errorf("saro: parsing sig ref: %w", err)
	}

	// Cosign signature image: single layer containing the payload,
	// with the base64 signature in a layer annotation.
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Layer = payload bytes with cosign media type
	layer := static.NewLayer(payload, types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json"))

	// Build image using addendum to set layer annotations
	adds := mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			"dev.cosignproject.cosign/signature": sigB64,
		},
	}

	img, err := mutate.Append(empty.Image, adds)
	if err != nil {
		return fmt.Errorf("saro: building sig image: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	// Set the manifest annotation with the digest of the signed image
	payloadHash := sha256.Sum256(payload)
	_ = payloadHash

	// Auth
	auth := opts.Auth
	if auth == nil {
		auth, err = Keychain.Resolve(sigRef.(name.Tag).Context())
		if err != nil {
			return fmt.Errorf("saro: resolving auth for sig: %w", err)
		}
	}

	remoteOpts := []remote.Option{
		remote.WithAuth(auth),
		remote.WithContext(ctx),
	}

	return remote.Write(sigRef, img, remoteOpts...)
}
