package saro

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestPush_OCILayoutDir(t *testing.T) {
	data := []byte("test content for OCI layout")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	outDir := filepath.Join(t.TempDir(), "oci-output")

	result, err := Push(context.Background(), PushOptions{
		SourceURL:  ts.URL + "/file.bin",
		OutputPath: outDir,
	})
	if err != nil {
		t.Fatalf("Push to OCI layout failed: %v", err)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", result.Size, len(data))
	}

	// Verify OCI layout structure
	if _, err := os.Stat(filepath.Join(outDir, "oci-layout")); err != nil {
		t.Error("missing oci-layout file")
	}
	if _, err := os.Stat(filepath.Join(outDir, "index.json")); err != nil {
		t.Error("missing index.json")
	}
	if _, err := os.Stat(filepath.Join(outDir, "blobs", "sha256")); err != nil {
		t.Error("missing blobs/sha256 directory")
	}
}

func TestPush_OCIArchiveTar(t *testing.T) {
	data := []byte("test content for OCI archive")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	tarPath := filepath.Join(t.TempDir(), "output.tar")

	result, err := Push(context.Background(), PushOptions{
		SourceURL:  ts.URL + "/file.bin",
		OutputPath: tarPath,
	})
	if err != nil {
		t.Fatalf("Push to OCI archive failed: %v", err)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", result.Size, len(data))
	}

	// Verify tar exists and has content
	info, err := os.Stat(tarPath)
	if err != nil {
		t.Fatal("tar file not created")
	}
	if info.Size() == 0 {
		t.Error("tar file is empty")
	}
}

func TestPush_OCILayoutWithChecksum(t *testing.T) {
	data := []byte("checksum test")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	outDir := filepath.Join(t.TempDir(), "oci-checksum")

	_, err := Push(context.Background(), PushOptions{
		SourceURL:      ts.URL + "/file",
		OutputPath:     outDir,
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("expected checksum error")
	}
}

func TestWriteOCIDir(t *testing.T) {
	img := buildOCIImage(staticTestLayer())
	dir := filepath.Join(t.TempDir(), "layout")

	if err := writeOCIDir(img, dir, "test:latest"); err != nil {
		t.Fatal(err)
	}

	if !fileExists(filepath.Join(dir, "oci-layout")) {
		t.Error("missing oci-layout")
	}
	if !fileExists(filepath.Join(dir, "index.json")) {
		t.Error("missing index.json")
	}
}

func TestWriteOCIArchive(t *testing.T) {
	img := buildOCIImage(staticTestLayer())
	tarPath := filepath.Join(t.TempDir(), "test.tar")

	if err := writeOCIArchive(img, tarPath, "test:latest"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(tarPath)
	if err != nil {
		t.Fatal("tar not created")
	}
	if info.Size() == 0 {
		t.Error("empty tar")
	}
}

func staticTestLayer() v1.Layer {
	return static.NewLayer([]byte("test"), types.MediaType("application/octet-stream"))
}
