# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.x     | Yes       |

## Reporting a Vulnerability

If you discover a security issue, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Security Advisories](https://github.com/genesary/saro/security/advisories/new) to report privately.

You should receive a response within 48 hours.

## Security Practices

This project follows security best practices:

- HTTP client with timeouts and redirect limits (no SSRF)
- No temp files or disk writes (streaming only)
- Registry credentials never logged or stored
- Signing key material handled via sigstore crypto primitives
- Container image runs as non-root (FROM scratch)
- All CI actions pinned by commit hash
- Release artifacts signed with cosign (Sigstore OIDC)
- SLSA provenance attestation on all releases
- OpenSSF Scorecard runs weekly
