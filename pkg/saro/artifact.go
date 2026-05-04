package saro

import (
	"encoding/json"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ociManifest is the OCI image manifest with the artifactType field
// that go-containerregistry v0.20.3 doesn't include on v1.Manifest.
type ociManifest struct {
	SchemaVersion int64             `json:"schemaVersion"`
	MediaType     types.MediaType   `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        v1.Descriptor     `json:"config"`
	Layers        []v1.Descriptor   `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Subject       *v1.Descriptor    `json:"subject,omitempty"`
}

// emptyConfigJSON is the OCI-spec-required content for application/vnd.oci.empty.v1+json.
var emptyConfigJSON = []byte("{}")

// emptyConfigDescriptor is precomputed since it never changes.
var emptyConfigDescriptor = func() v1.Descriptor {
	h, sz, _ := v1.SHA256(bytesReadCloser(emptyConfigJSON))
	return v1.Descriptor{
		MediaType: types.MediaType("application/vnd.oci.empty.v1+json"),
		Size:      sz,
		Digest:    h,
	}
}()

// artifactImage wraps a v1.Image to produce a proper OCI artifact manifest
// with artifactType and a spec-compliant empty config ({}, 2 bytes).
type artifactImage struct {
	v1.Image
	artifactType string
}

func (a *artifactImage) RawConfigFile() ([]byte, error) {
	return emptyConfigJSON, nil
}

func (a *artifactImage) Manifest() (*v1.Manifest, error) {
	return a.Image.Manifest()
}

func (a *artifactImage) RawManifest() ([]byte, error) {
	m, err := a.Image.Manifest()
	if err != nil {
		return nil, err
	}

	om := ociManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		ArtifactType:  a.artifactType,
		Config:        emptyConfigDescriptor,
		Layers:        m.Layers,
		Annotations:   m.Annotations,
		Subject:       m.Subject,
	}
	return json.Marshal(om)
}

func (a *artifactImage) Digest() (v1.Hash, error) {
	raw, err := a.RawManifest()
	if err != nil {
		return v1.Hash{}, err
	}
	d, _, err := v1.SHA256(bytesReadCloser(raw))
	return d, err
}

func (a *artifactImage) Size() (int64, error) {
	raw, err := a.RawManifest()
	if err != nil {
		return 0, err
	}
	return int64(len(raw)), nil
}

func (a *artifactImage) MediaType() (types.MediaType, error) {
	return types.OCIManifestSchema1, nil
}
