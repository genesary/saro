package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/genesary/saro/pkg/saro"
	"github.com/posener/complete/v2"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		sha256Flag     string
		mediaType      string
		artifactType   string
		insecure       bool
		quiet          bool
		sourceHeader   string
		signKey        string
		signKeyless    bool
		noTlog         bool
		registryConfig string
		annotations    stringSlice
	)

	flag.StringVar(&sha256Flag, "sha256", "", "Expected SHA256 hex digest for verification")
	flag.StringVar(&mediaType, "media-type", "", "Override layer media type")
	flag.StringVar(&artifactType, "artifact-type", "", "Override manifest artifact type")
	flag.BoolVar(&insecure, "insecure", false, "Allow HTTP (non-TLS) registries")
	flag.BoolVar(&quiet, "q", false, "Quiet mode — only print digest on success")
	flag.StringVar(&sourceHeader, "source-header", "", "Extra header for source HTTP request (e.g. \"Authorization: Bearer token\")")
	flag.StringVar(&signKey, "sign-key", "", "Sign with private key (path to cosign.key or PEM)")
	flag.BoolVar(&signKeyless, "sign", false, "Sign keyless via Fulcio/OIDC (needs COSIGN_IDENTITY_TOKEN)")
	flag.BoolVar(&noTlog, "no-tlog", false, "Skip Rekor transparency log upload")
	flag.StringVar(&registryConfig, "registry-config", "", "Path to Docker/Podman JSON credentials file")
	flag.Var(&annotations, "annotation", "OCI annotation (key=value), repeatable")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: saro [flags] <source-url | -> <destination>\n\n")
		fmt.Fprintf(os.Stderr, "Stream a URL directly into an OCI artifact.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	complete.CommandLine()
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	sourceURL := flag.Arg(0)
	destination := flag.Arg(1)

	opts := saro.PushOptions{
		SourceURL:      sourceURL,
		Destination:    destination,
		ExpectedSHA256: sha256Flag,
		MediaType:      mediaType,
		ArtifactType:   artifactType,
		Insecure:       insecure,
	}

	// Parse annotations
	if len(annotations) > 0 {
		opts.Annotations = make(map[string]string)
		for _, a := range annotations {
			k, v, ok := strings.Cut(a, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "error: invalid annotation format %q (expected key=value)\n", a)
				os.Exit(1)
			}
			opts.Annotations[k] = v
		}
	}

	// Source header
	if sourceHeader != "" {
		k, v, ok := strings.Cut(sourceHeader, ": ")
		if !ok {
			k, v, ok = strings.Cut(sourceHeader, ":")
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "error: invalid header format %q (expected \"Key: Value\")\n", sourceHeader)
			os.Exit(1)
		}
		opts.SourceHeaders = map[string]string{k: strings.TrimSpace(v)}
	}

	// Registry config override
	if registryConfig != "" {
		if _, err := os.Stat(registryConfig); err != nil {
			fmt.Fprintf(os.Stderr, "error: registry config not found: %s\n", registryConfig)
			os.Exit(1)
		}
		saro.Keychain = saro.KeychainFromConfig(registryConfig)
	}

	// Stdin mode
	if sourceURL == "-" {
		opts.Reader = os.Stdin
	}

	// Progress
	if !quiet {
		opts.OnProgress = func(downloaded, total int64) {
			if total > 0 {
				pct := float64(downloaded) / float64(total) * 100
				fmt.Fprintf(os.Stderr, "\r  ↓ %.1f%%  %s / %s", pct, saro.HumanBytes(downloaded), saro.HumanBytes(total))
			} else {
				fmt.Fprintf(os.Stderr, "\r  ↓ %s", saro.HumanBytes(downloaded))
			}
		}
	}

	ctx := context.Background()
	result, err := saro.Push(ctx, opts)
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		if errors.Is(err, saro.ErrChecksumMismatch) {
			os.Exit(2)
		}
		os.Exit(1)
	}

	if quiet {
		fmt.Println(result.Digest.String())
	} else {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  ✓ Pushed %s\n", result.Digest)
		fmt.Fprintf(os.Stderr, "    Size:     %s\n", saro.HumanBytes(result.Size))
		fmt.Fprintf(os.Stderr, "    Type:     %s\n", result.MediaType)
		fmt.Fprintf(os.Stderr, "    Artifact: %s\n", result.ArtifactType)
		fmt.Fprintf(os.Stderr, "    Dest:     %s\n", destination)
	}

	// Signing
	if signKey != "" || signKeyless {
		// Sign by digest to ensure we sign exactly what we pushed
		ref := result.Digest.String()
		parts := strings.SplitN(destination, ":", 2)
		imageRef := parts[0] + "@" + ref

		if !quiet {
			fmt.Fprintf(os.Stderr, "  ⟳ Signing %s...\n", imageRef)
		}

		var signErr error
		if signKey != "" {
			signErr = saro.Sign(ctx, imageRef, saro.SignOptions{
				KeyPath:  signKey,
				Insecure: insecure,
			})
		} else {
			signErr = saro.SignKeyless(ctx, imageRef, saro.KeylessSignOptions{
				SkipTlog: noTlog,
				Insecure: insecure,
			})
		}

		if signErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", signErr)
			os.Exit(1)
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "  ✓ Signed\n")
		}
	}
}

