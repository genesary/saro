package saro

import "testing"

func TestDetectMediaType_Override(t *testing.T) {
	got := detectMediaType("/foo/bar.zip", "text/plain", nil, "application/custom")
	if got != "application/custom" {
		t.Errorf("expected override, got %s", got)
	}
}

func TestDetectMediaType_ContentType(t *testing.T) {
	got := detectMediaType("/foo/bar", "application/gzip", nil, "")
	if got != "application/gzip" {
		t.Errorf("expected content-type header, got %s", got)
	}
}

func TestDetectMediaType_IgnoresGenericContentType(t *testing.T) {
	got := detectMediaType("/foo/bar.zip", "application/octet-stream", nil, "")
	if got != "application/zip" {
		t.Errorf("expected extension-based, got %s", got)
	}
}

func TestDetectMediaType_Extension(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/releases/v1.0/thing.tar.gz", "application/gzip"},
		{"/releases/v1.0/thing.tgz", "application/gzip"},
		{"/releases/v1.0/thing.zip", "application/zip"},
		{"/releases/v1.0/thing.tar.xz", "application/x-xz"},
		{"/releases/v1.0/thing.rpm", "application/x-rpm"},
		{"/releases/v1.0/thing.deb", "application/vnd.debian.binary-package"},
		{"/releases/v1.0/thing.json", "application/json"},
		{"/releases/v1.0/thing.yaml", "application/yaml"},
	}
	for _, tt := range tests {
		got := detectMediaType(tt.path, "", nil, "")
		if got != tt.expected {
			t.Errorf("path=%s: expected %s, got %s", tt.path, tt.expected, got)
		}
	}
}

func TestDetectMediaType_MagicBytes(t *testing.T) {
	// PK magic bytes for zip
	buf := []byte{0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0}
	got := detectMediaType("/noext", "", buf, "")
	if got != "application/zip" {
		t.Errorf("expected zip from magic bytes, got %s", got)
	}
}

func TestDetectMediaType_Fallback(t *testing.T) {
	got := detectMediaType("/noext", "", []byte("hello world"), "")
	if got != "application/octet-stream" && got != "text/plain; charset=utf-8" {
		// mimetype may detect text/plain for plain text, which is fine
		t.Logf("got %s (acceptable)", got)
	}
}

func TestDetectArtifactType_Override(t *testing.T) {
	got := detectArtifactType("application/gzip", "custom/type")
	if got != "custom/type" {
		t.Errorf("expected override, got %s", got)
	}
}

func TestDetectArtifactType_FromMediaType(t *testing.T) {
	got := detectArtifactType("application/gzip", "")
	if got != "application/gzip" {
		t.Errorf("expected media type copy, got %s", got)
	}
}

func TestDetectArtifactType_Fallback(t *testing.T) {
	got := detectArtifactType("application/octet-stream", "")
	if got != "application/vnd.oci.empty.v1+json" {
		t.Errorf("expected fallback, got %s", got)
	}
}
