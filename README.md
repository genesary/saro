<p align="center">
  <img src="logo.svg" alt="SARO" width="400"/>
</p>

<p align="center">
  <strong>Stream Artifacts to Registry from Origin</strong><br/>
  <em>URL in, OCI artifact out. One command. Zero temp files.</em>
</p>

<p align="center">
  <a href="https://github.com/genesary/saro/actions"><img src="https://github.com/genesary/saro/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://github.com/genesary/saro/releases"><img src="https://img.shields.io/github/v/release/genesary/saro" alt="Release"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"/></a>
  <a href="https://goreportcard.com/report/github.com/genesary/saro"><img src="https://goreportcard.com/badge/github.com/genesary/saro" alt="Go Report Card"/></a>
  <a href="https://codecov.io/gh/genesary/saro"><img src="https://codecov.io/gh/genesary/saro/branch/main/graph/badge.svg" alt="codecov"/></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/genesary/saro"><img src="https://api.scorecard.dev/projects/github.com/genesary/saro/badge" alt="OpenSSF Scorecard"/></a>
</p>

---

`saro` downloads a file from any HTTP(S) URL and pushes it as an OCI artifact to any OCI-compliant registry. No Docker, no daemon, no temp files. Stream straight from source to registry.

```bash
saro https://releases.hashicorp.com/terraform/1.8.0/terraform_1.8.0_linux_amd64.zip \
  harbor.internal/vendor/terraform:1.8.0
```

**ORAS backwards** - ORAS pulls artifacts *from* registries, SARO pushes artifacts *to* registries from any HTTP origin.

## Why

Every organization that air-gaps, vendors, or mirrors third-party dependencies ends up with the same fragile pipeline: `curl` > save to disk > `oras push` or `crane append` > cleanup. Three tools, temp files, error handling at every step.

`saro` replaces that with a single binary that streams the download directly into an OCI layer and pushes it. No intermediate files, no image store, no daemon.

## Install

**Homebrew**
```bash
brew install genesary/tap/saro
```

**From source**
```bash
go install github.com/genesary/saro/cmd/saro@latest
```

**Download binary**
```bash
curl -sL https://github.com/genesary/saro/releases/latest/download/saro_linux_amd64 -o saro
chmod +x saro
```

**Container image** (FROM scratch, ~12MB)
```bash
docker run --rm ghcr.io/genesary/saro:latest <url> <destination>
```

### Shell completion

```bash
# Install (bash/zsh/fish auto-detected)
COMP_INSTALL=1 saro

# Uninstall
COMP_UNINSTALL=1 saro
```

## Usage

```bash
# Basic: download and push
saro <source-url> <destination>

# With checksum verification
saro --sha256 abc123def456... <source-url> <destination>

# With custom annotations
saro --annotation "org.opencontainers.image.vendor=HashiCorp" \
     --annotation "org.opencontainers.image.version=1.8.0" \
     <source-url> <destination>

# Override media type and artifact type
saro --media-type application/gzip \
     --artifact-type "application/vnd.hashicorp.terraform.archive" \
     <source-url> <destination>

# Stdin (pipe from curl or anything)
curl -sL https://example.com/thing.tar.gz | saro - <destination>

# Quiet mode (just print digest)
saro -q <source-url> <destination>

# Insecure registry (HTTP)
saro --insecure <source-url> <destination>

# Use a specific credentials file
saro --registry-config /path/to/config.json <source-url> <destination>

# Save as OCI layout directory (no registry needed)
saro --output ./oci-layout <source-url>

# Save as OCI archive tarball
saro --output ./artifact.tar <source-url>

# OCI layout with a destination tag
saro --output ./oci-layout <source-url> <destination>

# Sign with cosign key
saro --sign-key cosign.key <source-url> <destination>

# Sign keyless (Fulcio/OIDC, for CI)
COSIGN_IDENTITY_TOKEN=$TOKEN saro --sign <source-url> <destination>
```

## Examples

### Vendor Terraform into Harbor

```bash
for v in 1.8.0 1.8.1 1.9.0; do
  saro "https://releases.hashicorp.com/terraform/${v}/terraform_${v}_linux_amd64.zip" \
    "harbor.internal/vendor/terraform:${v}"
done
```

### Mirror GitHub Release binaries

```bash
saro --annotation "org.opencontainers.image.source=https://github.com/cli/cli" \
  https://github.com/cli/cli/releases/download/v2.50.0/gh_2.50.0_linux_amd64.tar.gz \
  ghcr.io/myorg/vendor/gh-cli:2.50.0
```

### Cache CI dependencies as OCI artifacts

```bash
saro --sha256 $(curl -sL https://example.com/dep.tar.gz.sha256) \
  https://example.com/dep.tar.gz \
  registry.internal/ci-cache/dep:latest
```

### Air-gapped environment: vendor RPMs

```bash
saro https://mirror.centos.org/centos/8/extras/x86_64/Packages/epel-release-8.rpm \
  registry.internal/vendor/rpms/epel-release:8
```

### Air-gapped transfer via OCI layout

```bash
# On the connected machine: download to OCI archive
saro --output terraform.tar \
  https://releases.hashicorp.com/terraform/1.8.0/terraform_1.8.0_linux_amd64.zip

# Transfer terraform.tar to the air-gapped network (USB, sneakernet, etc.)

# On the air-gapped machine: push from OCI archive to internal registry
oras copy --from-oci-layout terraform.tar:latest harbor.internal/vendor/terraform:1.8.0
```

### Pipe from any command

```bash
# Pipe kubectl config
kubectl get configmap my-config -o json | saro - registry.internal/backups/configmap:latest

# Pipe a database dump
pg_dump mydb | gzip | saro --media-type application/gzip - registry.internal/backups/mydb:$(date +%Y%m%d)
```

### Push + sign in CI (GitHub Actions)

```yaml
- name: Push and sign artifact
  env:
    COSIGN_IDENTITY_TOKEN: ${{ steps.oidc.outputs.token }}
  run: |
    saro --sign \
      https://example.com/artifact.tar.gz \
      ghcr.io/myorg/artifacts/thing:${{ github.sha }}
```

### Push + sign with key

```bash
COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix mykey
saro --sign-key mykey.key https://example.com/file.zip registry.io/repo:tag

# Verify
cosign verify --key mykey.pub --insecure-ignore-tlog registry.io/repo:tag
```

## Features

- **Zero temp files** - streams HTTP body directly into OCI layer push
- **MIME auto-detection** - from Content-Type header, file extension, or magic bytes
- **SHA256 verification** - verify downloaded content before manifest commit
- **OCI annotations** - auto-generated source URL, checksum, timestamp, title
- **Cosign signing** - key-based and keyless (Fulcio/OIDC) signing
- **Stdin support** - pipe anything into an OCI artifact
- **Progress bar** - real-time download progress with percentage and size
- **Multi-credential support** - Docker, Podman, and credential helpers
- **Pure OCI artifact** - proper `artifactType`, empty config, spec-compliant manifest
- **Shell completion** - bash, zsh, fish auto-completion (`COMP_INSTALL=1 saro`)
- **OCI layout output** - save as OCI directory or tar archive (no registry needed)
- **12M static binary** - single binary, no runtime dependencies

## MIME Detection

Detection chain (highest priority first):

1. `--media-type` flag (user override)
2. HTTP `Content-Type` header (if not generic)
3. File extension from URL (`.tar.gz` > `application/gzip`, `.zip` > `application/zip`, etc.)
4. Magic bytes detection (first 512 bytes)
5. Fallback: `application/octet-stream`

## Auto-generated Annotations

Every push adds these to the OCI manifest:

| Annotation | Value |
|---|---|
| `org.opencontainers.image.source` | Source URL |
| `org.opencontainers.image.created` | RFC3339 timestamp |
| `org.opencontainers.image.title` | Filename from URL |
| `fr.saro.source.checksum` | SHA256 of downloaded content |
| `fr.saro.source.size` | Size in bytes |
| `fr.saro.source.content-type` | Original HTTP Content-Type |

Custom `--annotation` values merge with and can override any of the above.

## How streaming works

`saro` never writes to disk and never buffers the full file in memory. The data flows through a pipeline of `io.TeeReader` wrappers:

```
HTTP GET response body
  |
  +-> 512-byte buffer (MIME detection, one-time)
  |
  +-> io.TeeReader -> sha256 hasher + byte counter + progress callback
  |
  +-> stream.Layer (go-containerregistry)
  |
  +-> chunked upload to OCI registry
```

`stream.Layer` reads from the pipeline on-demand as the registry requests chunks. Total memory overhead is ~33KB regardless of file size. A 10GB file uses the same memory as a 10KB file.

## Authentication

Registry auth reads from (in order):

1. `--registry-config /path/to/config.json` (explicit override)
2. `$DOCKER_CONFIG/config.json`
3. `~/.docker/config.json`
4. `$XDG_RUNTIME_DIR/containers/auth.json` (Podman)
5. `~/.config/containers/auth.json` (Podman rootless)
6. Configured credential helpers (`docker-credential-*`)

For the source HTTP URL, use `--source-header "Authorization: Bearer <token>"`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (network, auth, etc.) |
| `2` | Checksum verification failed |

## Library Usage

`saro` is a Go library with a CLI wrapper. Import it directly:

```go
import "github.com/genesary/saro/pkg/saro"

// Push to registry
result, err := saro.Push(ctx, saro.PushOptions{
    SourceURL:   "https://example.com/file.tar.gz",
    Destination: "registry.io/repo:tag",
    ExpectedSHA256: "abc123...",
    OnProgress: func(downloaded, total int64) {
        fmt.Printf("\r%d / %d bytes", downloaded, total)
    },
})

// Or save to OCI layout directory
result, err := saro.Push(ctx, saro.PushOptions{
    SourceURL:  "https://example.com/file.tar.gz",
    OutputPath: "./oci-output",
})
```

## GitHub Action

```yaml
- uses: genesary/saro@v1
  with:
    source: https://example.com/artifact.tar.gz
    destination: ghcr.io/myorg/artifacts/thing:latest
    sha256: abc123def456...
    sign: true  # keyless signing with GitHub OIDC
```

## Use Cases

- Vendoring third-party binaries into Harbor/Zot/Quay for air-gapped environments
- CI pipelines that need to cache upstream dependencies as OCI artifacts
- Supply chain hygiene: every external dependency gets a checksum-verified, annotated, content-addressable copy in your registry
- Database backups, config snapshots, or any data piped into OCI storage
- Mirroring upstream releases with provenance annotations

## License

Apache-2.0
