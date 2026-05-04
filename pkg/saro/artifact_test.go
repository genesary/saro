package saro

import (
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestArtifactImage_RawManifest(t *testing.T) {
	layer := static.NewLayer([]byte("test"), types.MediaType("application/octet-stream"))
	img, _ := mutate.AppendLayers(empty.Image, layer)
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	ai := &artifactImage{Image: img, artifactType: "application/vnd.test"}

	raw, err := ai.RawManifest()
	if err != nil {
		t.Fatal(err)
	}

	var m ociManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if m.ArtifactType != "application/vnd.test" {
		t.Errorf("artifactType = %q, want application/vnd.test", m.ArtifactType)
	}

	if string(m.Config.MediaType) != "application/vnd.oci.empty.v1+json" {
		t.Errorf("config mediaType = %q, want empty", m.Config.MediaType)
	}

	if m.Config.Size != 2 {
		t.Errorf("config size = %d, want 2", m.Config.Size)
	}
}

func TestArtifactImage_Digest(t *testing.T) {
	layer := static.NewLayer([]byte("test"), types.MediaType("application/octet-stream"))
	img, _ := mutate.AppendLayers(empty.Image, layer)
	ai := &artifactImage{Image: img, artifactType: "test"}

	d, err := ai.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d.Algorithm != "sha256" {
		t.Errorf("algorithm = %s", d.Algorithm)
	}
	if d.Hex == "" {
		t.Error("empty hex digest")
	}
}

func TestArtifactImage_Size(t *testing.T) {
	layer := static.NewLayer([]byte("test"), types.MediaType("application/octet-stream"))
	img, _ := mutate.AppendLayers(empty.Image, layer)
	ai := &artifactImage{Image: img, artifactType: "test"}

	sz, err := ai.Size()
	if err != nil {
		t.Fatal(err)
	}
	if sz == 0 {
		t.Error("zero size")
	}
}

func TestArtifactImage_MediaType(t *testing.T) {
	ai := &artifactImage{Image: empty.Image, artifactType: "test"}
	mt, err := ai.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	if mt != types.OCIManifestSchema1 {
		t.Errorf("mediaType = %s", mt)
	}
}

func TestArtifactImage_RawConfigFile(t *testing.T) {
	ai := &artifactImage{Image: empty.Image, artifactType: "test"}
	cfg, err := ai.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg) != "{}" {
		t.Errorf("config = %q, want {}", string(cfg))
	}
}

func TestArtifactImage_Manifest(t *testing.T) {
	layer := static.NewLayer([]byte("test"), types.MediaType("application/octet-stream"))
	img, _ := mutate.AppendLayers(empty.Image, layer)
	ai := &artifactImage{Image: img, artifactType: "test"}

	m, err := ai.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("nil manifest")
	}
	if m.SchemaVersion != 2 {
		t.Errorf("schemaVersion = %d", m.SchemaVersion)
	}
}

func TestEmptyConfigDescriptor(t *testing.T) {
	if emptyConfigDescriptor.Size != 2 {
		t.Errorf("size = %d, want 2", emptyConfigDescriptor.Size)
	}
	if emptyConfigDescriptor.Digest.Hex == "" {
		t.Error("empty digest")
	}
}
