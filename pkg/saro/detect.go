package saro

import (
	"path"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

var extensionMap = map[string]string{
	".tar.gz":  "application/gzip",
	".tgz":     "application/gzip",
	".tar.bz2": "application/x-bzip2",
	".tar.xz":  "application/x-xz",
	".tar.zst": "application/zstd",
	".tar":     "application/x-tar",
	".zip":     "application/zip",
	".gz":      "application/gzip",
	".rpm":     "application/x-rpm",
	".deb":     "application/vnd.debian.binary-package",
	".bin":     "application/octet-stream",
	".exe":     "application/octet-stream",
	".json":    "application/json",
	".yaml":    "application/yaml",
	".yml":     "application/yaml",
}

// detectMediaType determines the layer media type using the detection chain:
// 1. User override (highest priority)
// 2. HTTP Content-Type header (if not generic)
// 3. File extension from URL path
// 4. Magic bytes detection
// 5. Fallback: application/octet-stream
func detectMediaType(urlPath, contentTypeHeader string, buf []byte, override string) string {
	if override != "" {
		return override
	}

	if contentTypeHeader != "" &&
		contentTypeHeader != "application/octet-stream" &&
		contentTypeHeader != "binary/octet-stream" &&
		!strings.HasPrefix(contentTypeHeader, "text/html") {
		// Strip parameters for OCI compliance
		ct := contentTypeHeader
		if idx := strings.Index(ct, ";"); idx != -1 {
			ct = strings.TrimSpace(ct[:idx])
		}
		return ct
	}

	if mt := mediaTypeFromExtension(urlPath); mt != "" {
		return mt
	}

	if len(buf) > 0 {
		mtype := mimetype.Detect(buf)
		mt := mtype.String()
		// Strip parameters (e.g. "; charset=utf-8") — OCI media types must be pure type/subtype
		if idx := strings.Index(mt, ";"); idx != -1 {
			mt = strings.TrimSpace(mt[:idx])
		}
		if mt != "application/octet-stream" {
			return mt
		}
	}

	return "application/octet-stream"
}

func mediaTypeFromExtension(urlPath string) string {
	p := strings.ToLower(path.Base(urlPath))
	// Check compound extensions first
	for ext, mt := range extensionMap {
		if strings.HasSuffix(p, ext) {
			return mt
		}
	}
	return ""
}

// detectArtifactType determines the manifest artifactType:
// 1. User override
// 2. Copy from detected media type
// 3. Fallback: application/vnd.oci.empty.v1+json
func detectArtifactType(mediaType, override string) string {
	if override != "" {
		return override
	}
	if mediaType != "" && mediaType != "application/octet-stream" {
		return mediaType
	}
	return "application/vnd.oci.empty.v1+json"
}
