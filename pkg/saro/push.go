package saro

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const userAgent = "saro/0.1 (+https://github.com/genesary/saro)"

// ErrChecksumMismatch is returned when SHA256 verification fails.
var ErrChecksumMismatch = errors.New("saro: checksum verification failed")

// httpClient with sane timeouts and redirect limits.
var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		// No idle timeout — streaming can take a while
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("saro: too many redirects")
		}
		return nil
	},
}

// Push streams a download from SourceURL directly into an OCI artifact
// and pushes it to the Destination registry. No temp files.
//
// The streaming pipeline:
//
//	HTTP body → [512B MIME buffer] → sha256+counter+progress → stream.Layer → registry
//
// Annotations that depend on the final hash/size cannot be set before the stream
// is consumed. Strategy:
//  1. First push: streams the layer blob to the registry.
//  2. After stream completes: verify checksum, then push final manifest with
//     full annotations. The layer blob already exists, so this is just a manifest write.
func Push(ctx context.Context, opts PushOptions) (*PushResult, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	// Parse destination early to fail fast on bad references.
	// For OCI layout output, destination is optional (used only as tag).
	var ref name.Reference
	if opts.Destination != "" {
		nameOpts := []name.Option{}
		if opts.Insecure {
			nameOpts = append(nameOpts, name.Insecure)
		}
		var err error
		ref, err = name.ParseReference(opts.Destination, nameOpts...)
		if err != nil && opts.OutputPath == "" {
			return nil, fmt.Errorf("saro: invalid destination: %w", err)
		}
	}

	var (
		body        io.ReadCloser
		contentType string
		urlPath     string
		totalSize   int64
	)

	if opts.Reader != nil {
		body = io.NopCloser(opts.Reader)
		urlPath = ""
		totalSize = opts.SizeHint
	} else if opts.SourceURL == "-" {
		return nil, errors.New("saro: stdin mode requires Reader to be set")
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.SourceURL, nil)
		if err != nil {
			return nil, fmt.Errorf("saro: creating request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range opts.SourceHeaders {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("saro: downloading: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("saro: HTTP %d from source", resp.StatusCode)
		}

		body = resp.Body
		contentType = resp.Header.Get("Content-Type")
		totalSize = resp.ContentLength

		if u, err := url.Parse(opts.SourceURL); err == nil {
			urlPath = u.Path
		}
	}
	defer func() { _ = body.Close() }()

	// Buffer first 512 bytes for MIME detection.
	buf := make([]byte, 512)
	n, err := io.ReadAtLeast(body, buf, 1)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("saro: reading source: %w", err)
	}
	buf = buf[:n]

	mediaType := detectMediaType(urlPath, contentType, buf, opts.MediaType)
	artifactType := detectArtifactType(mediaType, opts.ArtifactType)

	// Single streaming reader pipeline: buffered head + rest of body,
	// tapped by a combined hasher+counter+progress writer.
	reader := io.MultiReader(bytes.NewReader(buf), body)

	hasher := sha256.New()
	counter := &countWriter{}
	tap := &streamTap{
		hasher:     hasher,
		counter:    counter,
		onProgress: opts.OnProgress,
		total:      totalSize,
	}
	reader = io.TeeReader(reader, tap)

	// stream.Layer: consumed during push, zero temp files.
	layer := stream.NewLayer(io.NopCloser(reader), stream.WithMediaType(types.MediaType(mediaType)))

	if opts.OutputPath != "" {
		// OCI layout output: buffer the stream to a temp file (since we're
		// writing to disk anyway), then build the annotated image with full
		// annotations and write it to the OCI layout in one shot.
		tmpFile, err := os.CreateTemp("", "saro-layer-*")
		if err != nil {
			return nil, fmt.Errorf("saro: creating temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer func() { _ = os.Remove(tmpPath) }()

		if _, err := io.Copy(tmpFile, reader); err != nil {
			_ = tmpFile.Close()
			return nil, fmt.Errorf("saro: buffering source: %w", err)
		}
		_ = tmpFile.Close()

		// Stream consumed. Verify checksum.
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if opts.ExpectedSHA256 != "" {
			expected := strings.ToLower(strings.TrimPrefix(opts.ExpectedSHA256, "sha256:"))
			if actualHash != expected {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expected, actualHash)
			}
		}

		// Build annotated image with a static layer from the temp file.
		sourceURLAnn := opts.SourceURL
		if opts.Reader != nil && opts.SourceURL == "" {
			sourceURLAnn = "stdin"
		}
		annotations := buildAnnotations(sourceURLAnn, contentType, counter.n, actualHash, opts.Annotations)

		layerData, err := os.ReadFile(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("saro: reading temp layer: %w", err)
		}
		staticLayer := static.NewLayer(layerData, types.MediaType(mediaType))

		annotatedImg := buildOCIImage(staticLayer)
		annotatedImg = mutate.Annotations(annotatedImg, annotations).(v1.Image)
		var finalImg v1.Image = &artifactImage{Image: annotatedImg, artifactType: artifactType}

		if err := writeOCILayout(finalImg, opts.OutputPath, opts.Destination); err != nil {
			return nil, fmt.Errorf("saro: writing layout: %w", err)
		}

		digest, err := finalImg.Digest()
		if err != nil {
			return nil, fmt.Errorf("saro: computing digest: %w", err)
		}

		return &PushResult{
			Digest:       digest,
			Size:         counter.n,
			MediaType:    mediaType,
			ArtifactType: artifactType,
			SourceURL:    opts.SourceURL,
		}, nil
	}

	// Registry push path.
	img := buildOCIImage(layer)

	// Resolve auth.
	auth := opts.Auth
	if auth == nil {
		auth, err = Keychain.Resolve(ref.Context())
		if err != nil {
			return nil, fmt.Errorf("saro: resolving auth: %w", err)
		}
	}

	remoteOpts := []remote.Option{
		remote.WithAuth(auth),
		remote.WithContext(ctx),
	}

	// First push: uploads the layer blob + a minimal manifest.
	if err := remote.Write(ref, img, remoteOpts...); err != nil {
		return nil, fmt.Errorf("saro: pushing: %w", err)
	}

	// Stream fully consumed. Verify checksum.
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if opts.ExpectedSHA256 != "" {
		expected := strings.ToLower(strings.TrimPrefix(opts.ExpectedSHA256, "sha256:"))
		if actualHash != expected {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expected, actualHash)
		}
	}

	// Build full annotations now that we know size + hash.
	sourceURLAnn := opts.SourceURL
	if opts.Reader != nil && opts.SourceURL == "" {
		sourceURLAnn = "stdin"
	}
	annotations := buildAnnotations(sourceURLAnn, contentType, counter.n, actualHash, opts.Annotations)

	// Second push: manifest with annotations + artifactType.
	// The layer blob already exists in the registry. After consumption,
	// stream.Layer exposes its computed Digest/Size/DiffID, so it can be
	// reused as a static layer reference for manifest construction.
	annotatedImg := buildOCIImage(layer)
	annotatedImg = mutate.Annotations(annotatedImg, annotations).(v1.Image)
	var finalImg v1.Image = &artifactImage{Image: annotatedImg, artifactType: artifactType}

	if err := remote.Write(ref, finalImg, remoteOpts...); err != nil {
		return nil, fmt.Errorf("saro: pushing manifest: %w", err)
	}

	digest, err := finalImg.Digest()
	if err != nil {
		return nil, fmt.Errorf("saro: computing digest: %w", err)
	}

	return &PushResult{
		Digest:       digest,
		Size:         counter.n,
		MediaType:    mediaType,
		ArtifactType: artifactType,
		SourceURL:    opts.SourceURL,
	}, nil
}

// buildOCIImage creates an OCI manifest image with the given layer and empty config.
func buildOCIImage(layer v1.Layer) v1.Image {
	img, _ := mutate.AppendLayers(empty.Image, layer)
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType("application/vnd.oci.empty.v1+json"))
	return img
}

// streamTap combines sha256 hashing, byte counting, and progress reporting
// into a single io.Writer to avoid nested TeeReader overhead.
type streamTap struct {
	hasher     hash.Hash
	counter    *countWriter
	onProgress func(downloaded, total int64)
	total      int64
}

func (s *streamTap) Write(p []byte) (int, error) {
	s.hasher.Write(p)
	s.counter.n += int64(len(p))
	if s.onProgress != nil {
		s.onProgress(s.counter.n, s.total)
	}
	return len(p), nil
}

type countWriter struct {
	n int64
}
