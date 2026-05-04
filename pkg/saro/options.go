package saro

import (
	"errors"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// PushOptions configures a Push operation.
type PushOptions struct {
	// Required: HTTP(S) URL to download from, or "-" for stdin.
	SourceURL string
	// Required: registry/repo:tag destination.
	Destination string

	// Optional: if set, downloaded content is verified against this SHA256 hex digest.
	ExpectedSHA256 string

	// Optional: override detected layer media type.
	MediaType string
	// Optional: override detected artifact type.
	ArtifactType string
	// Optional: additional OCI annotations merged with auto-generated ones.
	Annotations map[string]string

	// Optional: registry authenticator. Defaults to authn.DefaultKeychain.
	Auth authn.Authenticator

	// Optional: allow HTTP (non-TLS) registries.
	Insecure bool

	// Optional: extra headers for the source HTTP request.
	SourceHeaders map[string]string

	// Optional: reader to use instead of HTTP GET (for stdin mode).
	Reader io.Reader

	// Optional: total size hint for progress (e.g. from Content-Length).
	SizeHint int64

	// Optional: progress callback. Called periodically with bytes downloaded and total.
	// Total is -1 if unknown (no Content-Length).
	OnProgress func(downloaded, total int64)

	// Optional: write to a local OCI layout instead of pushing to a registry.
	// Supports two formats:
	//   - Directory path (e.g. "./output") - writes OCI layout directory
	//   - Path ending in .tar (e.g. "./output.tar") - writes OCI archive tarball
	// When set, Destination is used only for the image reference tag, not for pushing.
	OutputPath string
}

// PushResult contains the result of a successful Push.
type PushResult struct {
	Digest       v1.Hash
	Size         int64
	MediaType    string
	ArtifactType string
	SourceURL    string
}

func (o *PushOptions) validate() error {
	if o.SourceURL == "" && o.Reader == nil {
		return errors.New("saro: SourceURL or Reader is required")
	}
	if o.Destination == "" && o.OutputPath == "" {
		return errors.New("saro: Destination or OutputPath is required")
	}
	return nil
}
