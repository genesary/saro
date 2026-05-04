package saro

import "testing"

func TestBuildAnnotations_Basic(t *testing.T) {
	ann := buildAnnotations(
		"https://example.com/thing.tar.gz",
		"application/gzip",
		1024,
		"abc123",
		nil,
	)

	if ann["org.opencontainers.image.source"] != "https://example.com/thing.tar.gz" {
		t.Error("missing source annotation")
	}
	if ann["org.opencontainers.image.title"] != "thing.tar.gz" {
		t.Errorf("unexpected title: %s", ann["org.opencontainers.image.title"])
	}
	if ann["fr.saro.source.checksum"] != "sha256:abc123" {
		t.Errorf("unexpected checksum: %s", ann["fr.saro.source.checksum"])
	}
	if ann["fr.saro.source.size"] != "1024" {
		t.Errorf("unexpected size: %s", ann["fr.saro.source.size"])
	}
	if ann["fr.saro.source.content-type"] != "application/gzip" {
		t.Errorf("unexpected content-type: %s", ann["fr.saro.source.content-type"])
	}
	if ann["org.opencontainers.image.created"] == "" {
		t.Error("missing created annotation")
	}
}

func TestBuildAnnotations_UserOverride(t *testing.T) {
	ann := buildAnnotations(
		"https://example.com/thing.tar.gz",
		"",
		0,
		"abc",
		map[string]string{
			"org.opencontainers.image.source": "custom-source",
			"custom.key":                      "custom-value",
		},
	)

	if ann["org.opencontainers.image.source"] != "custom-source" {
		t.Error("user override not applied")
	}
	if ann["custom.key"] != "custom-value" {
		t.Error("custom annotation not applied")
	}
}
