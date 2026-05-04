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
	outputPath     string
	annotations    stringSlice
)

func init() {
	flag.StringVar(&sha256Flag, "sha256", "", "Expected SHA256 hex digest for verification")
	flag.StringVar(&mediaType, "media-type", "", "Override layer media type")
	flag.StringVar(&artifactType, "artifact-type", "", "Override manifest artifact type")
	flag.BoolVar(&insecure, "insecure", false, "Allow HTTP (non-TLS) registries")
	flag.BoolVar(&quiet, "q", false, "Quiet mode - only print digest on success")
	flag.StringVar(&sourceHeader, "source-header", "", "Extra header for source HTTP request (e.g. \"Authorization: Bearer token\")")
	flag.StringVar(&signKey, "sign-key", "", "Sign with private key (path to cosign.key or PEM)")
	flag.BoolVar(&signKeyless, "sign", false, "Sign keyless via Fulcio/OIDC (needs COSIGN_IDENTITY_TOKEN)")
	flag.BoolVar(&noTlog, "no-tlog", false, "Skip Rekor transparency log upload")
	flag.StringVar(&registryConfig, "registry-config", "", "Path to Docker/Podman JSON credentials file")
	flag.StringVar(&outputPath, "output", "", "Write OCI layout to directory (or .tar archive) instead of pushing")
	flag.Var(&annotations, "annotation", "OCI annotation (key=value), repeatable")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: saro [flags] <source-url | -> <destination>\n\n")
		fmt.Fprintf(os.Stderr, "Stream a URL directly into an OCI artifact.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}

func main() {
	complete.CommandLine()
	flag.Parse()

	if err := run(); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		if errors.Is(err, saro.ErrChecksumMismatch) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run() error {
	sourceURL, destination := parseArgs()

	opts := buildPushOptions(sourceURL, destination)
	if err := applySourceHeader(&opts); err != nil {
		return err
	}
	applyRegistryConfig()
	applyStdin(&opts, sourceURL)
	applyProgress(&opts)

	ctx := context.Background()
	result, err := saro.Push(ctx, opts)
	if err != nil {
		return err
	}

	printResult(result, destination)
	return signIfRequested(ctx, result, destination)
}

func parseArgs() (sourceURL, destination string) {
	if outputPath != "" && flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	} else if outputPath == "" && flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	sourceURL = flag.Arg(0)
	if flag.NArg() >= 2 {
		destination = flag.Arg(1)
	}
	return
}

func buildPushOptions(sourceURL, destination string) saro.PushOptions {
	opts := saro.PushOptions{
		SourceURL:      sourceURL,
		Destination:    destination,
		ExpectedSHA256: sha256Flag,
		MediaType:      mediaType,
		ArtifactType:   artifactType,
		Insecure:       insecure,
		OutputPath:     outputPath,
	}

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
	return opts
}

func applySourceHeader(opts *saro.PushOptions) error {
	if sourceHeader == "" {
		return nil
	}
	k, v, ok := strings.Cut(sourceHeader, ": ")
	if !ok {
		k, v, ok = strings.Cut(sourceHeader, ":")
	}
	if !ok {
		return fmt.Errorf("invalid header format %q (expected \"Key: Value\")", sourceHeader)
	}
	opts.SourceHeaders = map[string]string{k: strings.TrimSpace(v)}
	return nil
}

func applyRegistryConfig() {
	if registryConfig == "" {
		return
	}
	if _, err := os.Stat(registryConfig); err != nil {
		fmt.Fprintf(os.Stderr, "error: registry config not found: %s\n", registryConfig)
		os.Exit(1)
	}
	saro.Keychain = saro.KeychainFromConfig(registryConfig)
}

func applyStdin(opts *saro.PushOptions, sourceURL string) {
	if sourceURL == "-" {
		opts.Reader = os.Stdin
	}
}

func applyProgress(opts *saro.PushOptions) {
	if quiet {
		return
	}
	opts.OnProgress = func(downloaded, total int64) {
		if total > 0 {
			pct := float64(downloaded) / float64(total) * 100
			fmt.Fprintf(os.Stderr, "\r  ↓ %.1f%%  %s / %s", pct, saro.HumanBytes(downloaded), saro.HumanBytes(total))
		} else {
			fmt.Fprintf(os.Stderr, "\r  ↓ %s", saro.HumanBytes(downloaded))
		}
	}
}

func printResult(result *saro.PushResult, destination string) {
	if quiet {
		fmt.Println(result.Digest.String())
		return
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ✓ Pushed %s\n", result.Digest)
	fmt.Fprintf(os.Stderr, "    Size:     %s\n", saro.HumanBytes(result.Size))
	fmt.Fprintf(os.Stderr, "    Type:     %s\n", result.MediaType)
	fmt.Fprintf(os.Stderr, "    Artifact: %s\n", result.ArtifactType)
	fmt.Fprintf(os.Stderr, "    Dest:     %s\n", destination)
}

func signIfRequested(ctx context.Context, result *saro.PushResult, destination string) error {
	if signKey == "" && !signKeyless {
		return nil
	}

	ref := result.Digest.String()
	parts := strings.SplitN(destination, ":", 2)
	imageRef := parts[0] + "@" + ref

	if !quiet {
		fmt.Fprintf(os.Stderr, "  ⟳ Signing %s...\n", imageRef)
	}

	var err error
	if signKey != "" {
		err = saro.Sign(ctx, imageRef, saro.SignOptions{KeyPath: signKey, Insecure: insecure})
	} else {
		err = saro.SignKeyless(ctx, imageRef, saro.KeylessSignOptions{SkipTlog: noTlog, Insecure: insecure})
	}
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "  ✓ Signed\n")
	}
	return nil
}
