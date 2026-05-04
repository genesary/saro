package saro

import (
	"fmt"
	"path"
	"time"
)

// buildAnnotations creates the OCI annotation map, merging auto-generated
// annotations with user-provided ones. User annotations take precedence.
func buildAnnotations(sourceURL, contentType string, size int64, sha256Hex string, userAnnotations map[string]string) map[string]string {
	ann := map[string]string{
		"org.opencontainers.image.source":  sourceURL,
		"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
		"fr.saro.source.checksum":       "sha256:" + sha256Hex,
		"fr.saro.source.size":           fmt.Sprintf("%d", size),
	}

	if title := path.Base(sourceURL); title != "" && title != "." && title != "/" {
		ann["org.opencontainers.image.title"] = title
	}

	if contentType != "" {
		ann["fr.saro.source.content-type"] = contentType
	}

	for k, v := range userAnnotations {
		ann[k] = v
	}

	return ann
}
