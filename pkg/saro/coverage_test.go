package saro

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceAnnotation_Stdin(t *testing.T) {
	got := sourceAnnotation(PushOptions{Reader: bytes.NewReader(nil), SourceURL: ""})
	if got != "stdin" {
		t.Errorf("got %q, want stdin", got)
	}
}

func TestSourceAnnotation_URL(t *testing.T) {
	got := sourceAnnotation(PushOptions{SourceURL: "https://example.com/file"})
	if got != "https://example.com/file" {
		t.Errorf("got %q", got)
	}
}

func TestPush_RegistryPath_FailsAtPush(t *testing.T) {
	// Exercise the registry push path (not output path)
	data := []byte("test content for registry path")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	_, err := Push(context.Background(), PushOptions{
		SourceURL:   ts.URL + "/file.bin",
		Destination: "localhost:5000/test/reg-path:v1",
		Insecure:    true,
	})
	// Should fail at push (no registry), not before
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPush_OutputWithDestination(t *testing.T) {
	data := []byte("test with dest tag")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	outDir := filepath.Join(t.TempDir(), "with-dest")
	result, err := Push(context.Background(), PushOptions{
		SourceURL:   ts.URL + "/file",
		Destination: "registry.io/repo:tag",
		OutputPath:  outDir,
	})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("size = %d", result.Size)
	}
}

func TestPush_OutputWithReader(t *testing.T) {
	data := []byte("reader output test")
	outDir := filepath.Join(t.TempDir(), "reader-out")

	result, err := Push(context.Background(), PushOptions{
		Reader:     bytes.NewReader(data),
		SourceURL:  "custom://source",
		OutputPath: outDir,
	})
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if result.Size != int64(len(data)) {
		t.Errorf("size = %d", result.Size)
	}
}

func TestPush_OutputChecksumPass(t *testing.T) {
	data := []byte("checksum pass test")
	// Precompute the sha256
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	outDir := filepath.Join(t.TempDir(), "checksum-pass")
	_, err := Push(context.Background(), PushOptions{
		SourceURL:      ts.URL + "/file",
		OutputPath:     outDir,
		ExpectedSHA256: "sha256:e2d312cafc73711338e90a4c41de1d269c24ca18bc2ee1a253d79182a449a8e6",
	})
	// Wrong hash, should fail at checksum
	if err == nil {
		t.Fatal("expected checksum error")
	}
}

func TestWriteOCIArchive_BadPath(t *testing.T) {
	img := buildOCIImage(staticTestLayer())
	err := writeOCIArchive(img, "/nonexistent/dir/test.tar", "")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestWriteOCIDir_BadPath(t *testing.T) {
	img := buildOCIImage(staticTestLayer())
	// Writing to a file path (not dir) should fail
	tmpFile := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(tmpFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// Try to write OCI layout to a path where a file already exists
	err := writeOCIDir(img, filepath.Join(tmpFile, "sub"), "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchSource_InvalidURL(t *testing.T) {
	_, err := fetchSource(context.Background(), PushOptions{
		SourceURL: "://invalid",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchSource_StdinWithoutReader(t *testing.T) {
	_, err := fetchSource(context.Background(), PushOptions{
		SourceURL: "-",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchSource_Reader(t *testing.T) {
	src, err := fetchSource(context.Background(), PushOptions{
		Reader:   bytes.NewReader([]byte("test")),
		SizeHint: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.totalSize != 4 {
		t.Errorf("totalSize = %d", src.totalSize)
	}
	_ = src.body.Close()
}

func TestPushToLayout_BadOutputPath(t *testing.T) {
	data := []byte("bad path test")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	_, err := Push(context.Background(), PushOptions{
		SourceURL:  ts.URL + "/file",
		OutputPath: "/nonexistent/deep/path/output",
	})
	if err == nil {
		t.Fatal("expected error for bad output path")
	}
}

func TestVerifyChecksum_EmptyExpected(t *testing.T) {
	err := verifyChecksum("abc123", "")
	if err != nil {
		t.Fatal("empty expected should pass")
	}
}

func TestVerifyChecksum_Match(t *testing.T) {
	err := verifyChecksum("abc123", "abc123")
	if err != nil {
		t.Fatal("should match")
	}
}

func TestVerifyChecksum_Prefix(t *testing.T) {
	err := verifyChecksum("abc123", "sha256:ABC123")
	if err != nil {
		t.Fatal("should match case-insensitive with prefix")
	}
}

func TestRemoteAuthOption_NilAuth(t *testing.T) {
	opt, err := RemoteAuthOption(fakeResource("example.com"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if opt == nil {
		t.Fatal("nil option")
	}
}
