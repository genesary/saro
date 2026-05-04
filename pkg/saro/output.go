package saro

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// writeOCILayout writes an image to an OCI layout directory or tar archive.
// If outputPath ends with ".tar", it creates a tar archive.
// Otherwise, it writes an OCI layout directory.
func writeOCILayout(img v1.Image, outputPath, tag string) error {
	if strings.HasSuffix(outputPath, ".tar") {
		return writeOCIArchive(img, outputPath, tag)
	}
	return writeOCIDir(img, outputPath, tag)
}

// writeOCIDir writes an image to an OCI layout directory.
func writeOCIDir(img v1.Image, dir, tag string) error {
	// Initialize an empty OCI layout, then append the image.
	// AppendImage handles stream.Layer consumption properly.
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return fmt.Errorf("saro: writing OCI layout: %w", err)
	}

	if err := lp.AppendImage(img); err != nil {
		return fmt.Errorf("saro: appending image: %w", err)
	}

	return nil
}

// writeOCIArchive writes an image as an OCI layout tar archive.
func writeOCIArchive(img v1.Image, tarPath, tag string) error {
	// Write to a temp dir first, then tar it
	tmpDir, err := os.MkdirTemp("", "saro-oci-*")
	if err != nil {
		return fmt.Errorf("saro: creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := writeOCIDir(img, tmpDir, tag); err != nil {
		return err
	}

	// Create tar archive
	f, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("saro: creating archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()

	return filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path for tar header
		relPath, err := filepath.Rel(tmpDir, path)
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()

		_, err = io.Copy(tw, file)
		return err
	})
}
