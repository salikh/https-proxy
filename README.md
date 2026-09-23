# HTTPS Reverse Proxy with Automated Let's Encrypt & Redirection

A high-performance Go reverse proxy designed to expose local or internal HTTP backend applications securely over HTTPS with automatic Let's Encrypt (ACME) certificate provisioning, self-signed certificate support, and automated HTTP-to-HTTPS redirection.

---

## Features

- **Google OAuth 2.0 Access Control**: Enforces mandatory Google OAuth login on all requests when `--oauth` is enabled, forwarding verified user email headers (`X-Forwarded-User`, `X-Auth-Email`) to the backend.
- **ACME Challenge Exemption**: Preserves HTTP-01 challenge paths (`/.well-known/acme-challenge/*`) unconditionally, exempting them from OAuth authentication and redirection loops to guarantee seamless Let's Encrypt certificate issuance.
- **Client Secret Protection Defense-in-Depth**:
  - Automatic `0600` file permission tightening for secret credentials.
  - Authenticated AES-256-GCM encryption at rest (`secret.json.enc`) via PBKDF2 with CLI tool and `encrypt-secret.sh`.
  - Zero-disk credential loading via `OAUTH_SECRET_JSON` environment variable.
  - Query parameter log sanitization (redacting `code`, `state`, `secret`, `token`).
  - Cryptographically signed HMAC-SHA256 HttpOnly/Secure session cookies and CSRF state tokens.
- **Allowed Users Whitelist**: Supports restricting access via `allowed.txt` (loaded automatically), command-line user lists (`--oauth-allowed-users`), and domain whitelists (`--oauth-allowed-domains`).
- **Automated TLS via Let's Encrypt**: Automatic certificate issuance and renewal via ACME HTTP-01 / TLS-ALPN using `golang.org/x/crypto/acme/autocert`.
- **Automated HTTP-to-HTTPS Redirection**: Automatically redirects plain HTTP requests on port 80 to the canonical HTTPS service with `301 Moved Permanently`.
- **LAN IP & Non-SNI Canonicalization**: Automatically canonicalizes requests directed at LAN IPs (e.g., `http://192.168.1.1`) to the configured domain, preventing TLS handshake errors (`acme/autocert: missing server name`).
- **Multiple Certificate Modes**:
  - Let's Encrypt automated certificates (default)
  - Self-signed certificates for testing and offline setups
  - Manual certificates (`--cert` and `--key`)
  - Plain HTTP proxy mode (`--no-tls`)
- **Production-Ready Proxy Engine**: Built-in hop-by-hop header stripping, `X-Forwarded-*` header management, custom path prefix routing, and graceful shutdown handling.

---

## Quick Start

### 1. Build the Binary

```bash
./build.sh
```

### 2. Run with Let's Encrypt & OAuth Authentication (Production Mode)

Using `start.sh`:
```bash
sudo ./start.sh --hostname part.salikh.info --backend http://192.168.1.11:8080 --oauth --verbose
```

Or running the binary directly:
```bash
sudo ./https-proxy --hostname part.salikh.info --backend http://192.168.1.11:8080 --oauth --verbose
```

### 3. Run with Self-Signed Certificates (Local Development / Testing)

```bash
# Generate self-signed cert for testing
./generate-self-signed-cert.sh --hostname myserver.local --output-dir ./certs

# Run proxy in self-signed mode
sudo ./start.sh --hostname myserver.local --backend http://192.168.1.11:8080 --self-signed --self-signed-dir ./certs
```

### 4. Encrypting OAuth Client Secrets at Rest

Protect your `secret.json` from disk exposure:
```bash
# Encrypt credentials into AES-256-GCM container
./encrypt-secret.sh secret.json secret.json.enc

# Safely delete plaintext secret
rm secret.json

# Run proxy using the encrypted credentials
export OAUTH_PASSPHRASE="your-passphrase"
sudo ./start.sh --hostname part.salikh.info --backend http://192.168.1.11:8080 --oauth --oauth-secret secret.json.enc
```

---

## Command Line Flags & Usage Instructions

Both `./https-proxy` and `./start.sh` accept the following flags:

```text
Usage: ./https-proxy [options]

Required Options:
  --backend URL            Backend HTTP address to proxy to (required, e.g. http://192.168.1.11:8080)
  --hostname HOSTNAME      Hostname for the server (required for HTTPS mode, e.g. part.salikh.info)

Network & Port Options:
  --port PORT              Port to listen on for HTTPS (default: 443)
  --http-port PORT         Port to listen on for HTTP challenges/redirects (default: 80)

Certificate Modes:
  (default)                Let's Encrypt mode using autocert (automatic issuance and renewal)
  --cache-dir DIR          Directory to cache Let's Encrypt certificates (default: ~/.cache/https-proxy)
  --self-signed            Use self-signed certificates instead of Let's Encrypt
  --self-signed-dir DIR    Directory containing cert.pem & key.pem (default: ~/.cache/https-proxy-selfsigned)
  --cert FILE              Path to certificate file (for manual cert management)
  --key FILE               Path to private key file (for manual cert management)
  --no-tls                 Run as plain HTTP proxy without TLS

Logging & Diagnostics:
  --verbose                Enable verbose request, response, and redirection logging

OAuth 2.0 Access Control:
  --oauth                  Enforce Google OAuth 2.0 authentication on all requests (except ACME)
  --oauth-secret FILE      Path to credentials JSON (plaintext or .enc, default: secret.json)
  --oauth-passphrase PASS  Passphrase for encrypted credentials (or OAUTH_PASSPHRASE env var)
  --oauth-allowed-file FILE Path to allowed emails whitelist (default: allowed.txt if exists)
  --oauth-allowed-users LIST Comma-separated list of allowed user email addresses
  --oauth-allowed-domains LIST Comma-separated list of allowed Google Workspace domains
```

For the complete flag matrix and detailed parameter rules, see [**CLI Reference**](docs/cli-reference.md).

---

## Detailed Documentation

Comprehensive documentation of design decisions, architecture, and deployment setup can be found in the [`docs/`](docs/) directory:

- [**OAuth 2.0 Authentication & Secret Protection**](docs/oauth-authentication.md): Architecture of OAuth gateway, ACME challenge bypass, whitelist rules, and multi-layered defense strategy for client secrets.
- [**CLI Reference**](docs/cli-reference.md): Detailed matrix of all flags, default values, requirements, and invocation examples.
- [**Architecture & Proxy Pipeline**](docs/architecture.md): Overview of request processing, reverse proxy director, header transformations, and graceful shutdown.
- [**HTTP Redirection & ACME Challenges**](docs/redirect-and-acme.md): Deep dive into the HTTP-to-HTTPS redirect logic, ACME HTTP-01 challenge exemption, LAN IP canonicalization, and SNI fallback mechanisms.
- [**Certificate Management Modes**](docs/certificates.md): Let's Encrypt lifecycle, self-signed certificates, and manual certificate configuration.
- [**Networking, IPv6, and Firewall Setup**](docs/deployment-and-firewall.md): Dual-stack IPv4/IPv6 routing, Let's Encrypt reachability, `ip6tables`/`iptables` rules, and persistent Debian configuration.
