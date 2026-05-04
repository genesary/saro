package saro

import (
	"bytes"
	"context"
	"testing"
)

func FuzzDetectMediaType(f *testing.F) {
	f.Add("/file.tar.gz", "application/gzip", []byte{0x1f, 0x8b}, "")
	f.Add("/file.zip", "", []byte{0x50, 0x4B, 0x03, 0x04}, "")
	f.Add("/file.rpm", "application/octet-stream", []byte{0xed, 0xab, 0xee, 0xdb}, "")
	f.Add("/noext", "", []byte("hello world"), "")
	f.Add("", "", []byte{}, "")
	f.Add("/file.json", "application/json", []byte(`{"key":"value"}`), "")
	f.Add("/deep/path/file.tar.xz", "binary/octet-stream", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "")
	f.Add("/file", "text/plain; charset=utf-8", []byte("plain text"), "application/custom")

	f.Fuzz(func(t *testing.T, urlPath, contentType string, buf []byte, override string) {
		// Should never panic
		result := detectMediaType(urlPath, contentType, buf, override)
		if result == "" {
			t.Error("empty media type returned")
		}
	})
}

func FuzzDetectArtifactType(f *testing.F) {
	f.Add("application/gzip", "")
	f.Add("application/octet-stream", "")
	f.Add("application/zip", "custom/type")
	f.Add("", "")
	f.Add("text/plain", "")

	f.Fuzz(func(t *testing.T, mediaType, override string) {
		result := detectArtifactType(mediaType, override)
		if result == "" {
			t.Error("empty artifact type returned")
		}
	})
}

func FuzzBuildAnnotations(f *testing.F) {
	f.Add("https://example.com/file.tar.gz", "application/gzip", int64(1024), "abc123")
	f.Add("", "", int64(0), "")
	f.Add("https://evil.com/<script>alert(1)</script>", "text/html", int64(-1), "not-a-hash")

	f.Fuzz(func(t *testing.T, sourceURL, contentType string, size int64, sha256Hex string) {
		result := buildAnnotations(sourceURL, contentType, size, sha256Hex, nil)
		if result == nil {
			t.Error("nil annotations")
		}
		if result["fr.saro.source.checksum"] == "" {
			t.Error("missing checksum annotation")
		}
	})
}

func FuzzCosignPayload(f *testing.F) {
	f.Add("registry.io/repo@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1")
	f.Add("localhost:5000/test@sha256:0000000000000000000000000000000000000000000000000000000000000000")

	f.Fuzz(func(t *testing.T, ref string) {
		digest, err := newTestDigest(ref)
		if err != nil {
			return // invalid ref, skip
		}
		payload, err := cosignPayload(digest)
		if err != nil {
			t.Fatalf("cosignPayload failed: %v", err)
		}
		if len(payload) == 0 {
			t.Error("empty payload")
		}
	})
}

func FuzzPushValidation(f *testing.F) {
	f.Add("https://example.com/file", "registry/repo:tag", "abc123", false)
	f.Add("", "", "", true)
	f.Add("-", "registry/repo:tag", "", false)

	f.Fuzz(func(t *testing.T, sourceURL, destination, sha256 string, useReader bool) {
		opts := PushOptions{
			SourceURL:      sourceURL,
			Destination:    destination,
			ExpectedSHA256: sha256,
		}
		if useReader {
			opts.Reader = bytes.NewReader([]byte("test"))
		}
		// validate should never panic
		_ = opts.validate()
	})
}

func FuzzHumanBytes(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(512))
	f.Add(int64(1024))
	f.Add(int64(1048576))
	f.Add(int64(1073741824))
	f.Add(int64(-1))
	f.Add(int64(9223372036854775807)) // max int64

	f.Fuzz(func(t *testing.T, b int64) {
		result := HumanBytes(b)
		if result == "" {
			t.Error("empty result")
		}
	})
}

func FuzzVerifyChecksum(f *testing.F) {
	f.Add("abc123", "abc123")
	f.Add("abc123", "sha256:abc123")
	f.Add("abc123", "ABC123")
	f.Add("abc123", "wrong")
	f.Add("abc123", "")

	f.Fuzz(func(t *testing.T, actual, expected string) {
		// Should never panic
		_ = verifyChecksum(actual, expected)
	})
}

func FuzzPushToLayoutSmoke(f *testing.F) {
	f.Add([]byte("test content"), "application/octet-stream")
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04}, "application/zip")
	f.Add([]byte(`{"json":true}`), "application/json")

	f.Fuzz(func(t *testing.T, data []byte, mediaType string) {
		if len(data) == 0 || mediaType == "" {
			return
		}
		ctx := context.Background()
		outDir := t.TempDir()

		// This exercises the full OCI layout path with arbitrary data
		_, _ = Push(ctx, PushOptions{
			Reader:     bytes.NewReader(data),
			SourceURL:  "fuzz://test",
			OutputPath: outDir,
			MediaType:  mediaType,
		})
	})
}
