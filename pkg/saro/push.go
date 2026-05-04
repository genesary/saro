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
//
// streamState holds the prepared streaming pipeline state.
type streamState struct {
	reader       io.Reader
	layer        v1.Layer
	hasher       hash.Hash
	counter      *countWriter
	src          *sourceResult
	mediaType    string
	artifactType string
}

// prepareStream sets up the source download and streaming pipeline.
func prepareStream(ctx context.Context, opts PushOptions) (*streamState, error) {
	src, err := fetchSource(ctx, opts)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := io.ReadAtLeast(src.body, buf, 1)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		_ = src.body.Close()
		return nil, fmt.Errorf("saro: reading source: %w", err)
	}
	buf = buf[:n]

	mediaType := detectMediaType(src.urlPath, src.contentType, buf, opts.MediaType)
	artifactType := detectArtifactType(mediaType, opts.ArtifactType)

	reader := io.MultiReader(bytes.NewReader(buf), src.body)
	hasher := sha256.New()
	counter := &countWriter{}
	tap := &streamTap{hasher: hasher, counter: counter, onProgress: opts.OnProgress, total: src.totalSize}
	reader = io.TeeReader(reader, tap)
	layer := stream.NewLayer(io.NopCloser(reader), stream.WithMediaType(types.MediaType(mediaType)))

	return &streamState{
		reader: reader, layer: layer, hasher: hasher, counter: counter,
		src: src, mediaType: mediaType, artifactType: artifactType,
	}, nil
}

func Push(ctx context.Context, opts PushOptions) (*PushResult, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

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

	ss, err := prepareStream(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ss.src.body.Close() }()

	if opts.OutputPath != "" {
		return pushToLayout(ss, opts)
	}

	// Registry push path.
	img := buildOCIImage(ss.layer)

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

	if err := remote.Write(ref, img, remoteOpts...); err != nil {
		return nil, fmt.Errorf("saro: pushing: %w", err)
	}

	actualHash := hex.EncodeToString(ss.hasher.Sum(nil))
	if err := verifyChecksum(actualHash, opts.ExpectedSHA256); err != nil {
		return nil, err
	}

	annotations := buildAnnotations(sourceAnnotation(opts), ss.src.contentType, ss.counter.n, actualHash, opts.Annotations)
	finalImg := buildAnnotatedArtifact(ss.layer, ss.mediaType, ss.artifactType, annotations)

	if err := remote.Write(ref, finalImg, remoteOpts...); err != nil {
		return nil, fmt.Errorf("saro: pushing manifest: %w", err)
	}

	digest, err := finalImg.Digest()
	if err != nil {
		return nil, fmt.Errorf("saro: computing digest: %w", err)
	}
	return &PushResult{Digest: digest, Size: ss.counter.n, MediaType: ss.mediaType, ArtifactType: ss.artifactType, SourceURL: opts.SourceURL}, nil
}

// pushToLayout writes the artifact to an OCI layout directory or tar archive.
func pushToLayout(ss *streamState, opts PushOptions) (*PushResult, error) {
	tmpFile, err := os.CreateTemp("", "saro-layer-*")
	if err != nil {
		return nil, fmt.Errorf("saro: creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := io.Copy(tmpFile, ss.reader); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("saro: buffering source: %w", err)
	}
	_ = tmpFile.Close()

	actualHash := hex.EncodeToString(ss.hasher.Sum(nil))
	if err := verifyChecksum(actualHash, opts.ExpectedSHA256); err != nil {
		return nil, err
	}

	annotations := buildAnnotations(sourceAnnotation(opts), ss.src.contentType, ss.counter.n, actualHash, opts.Annotations)
	layerData, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("saro: reading temp layer: %w", err)
	}

	finalImg := buildAnnotatedArtifact(
		static.NewLayer(layerData, types.MediaType(ss.mediaType)),
		ss.mediaType, ss.artifactType, annotations,
	)
	if err := writeOCILayout(finalImg, opts.OutputPath, opts.Destination); err != nil {
		return nil, fmt.Errorf("saro: writing layout: %w", err)
	}

	digest, err := finalImg.Digest()
	if err != nil {
		return nil, fmt.Errorf("saro: computing digest: %w", err)
	}
	return &PushResult{Digest: digest, Size: ss.counter.n, MediaType: ss.mediaType, ArtifactType: ss.artifactType, SourceURL: opts.SourceURL}, nil
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

type sourceResult struct {
	body        io.ReadCloser
	contentType string
	urlPath     string
	totalSize   int64
}

// fetchSource opens the source reader from HTTP or stdin.
func fetchSource(ctx context.Context, opts PushOptions) (*sourceResult, error) {
	if opts.Reader != nil {
		return &sourceResult{body: io.NopCloser(opts.Reader), totalSize: opts.SizeHint}, nil
	}
	if opts.SourceURL == "-" {
		return nil, errors.New("saro: stdin mode requires Reader to be set")
	}

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

	r := &sourceResult{
		body:        resp.Body,
		contentType: resp.Header.Get("Content-Type"),
		totalSize:   resp.ContentLength,
	}
	if u, err := url.Parse(opts.SourceURL); err == nil {
		r.urlPath = u.Path
	}
	return r, nil
}

// verifyChecksum checks the actual hash against the expected one.
func verifyChecksum(actual, expected string) error {
	if expected == "" {
		return nil
	}
	expected = strings.ToLower(strings.TrimPrefix(expected, "sha256:"))
	if actual != expected {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expected, actual)
	}
	return nil
}

// buildAnnotatedArtifact creates the final OCI artifact image with annotations.
func buildAnnotatedArtifact(layer v1.Layer, mediaType, artifactType string, annotations map[string]string) v1.Image {
	img := buildOCIImage(layer)
	img = mutate.Annotations(img, annotations).(v1.Image)
	return &artifactImage{Image: img, artifactType: artifactType}
}

// sourceAnnotation returns the source URL for annotations.
func sourceAnnotation(opts PushOptions) string {
	if opts.Reader != nil && opts.SourceURL == "" {
		return "stdin"
	}
	return opts.SourceURL
}
