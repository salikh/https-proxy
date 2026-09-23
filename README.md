# HTTPS Reverse Proxy with Automated Let's Encrypt & Redirection

A high-performance Go reverse proxy designed to expose local or internal HTTP backend applications securely over HTTPS with automatic Let's Encrypt (ACME) certificate provisioning, self-signed certificate support, and automated HTTP-to-HTTPS redirection.

---

## Features

- **Automated TLS via Let's Encrypt**: Automatic certificate issuance and renewal via ACME HTTP-01 / TLS-ALPN using `golang.org/x/crypto/acme/autocert`.
- **Automated HTTP-to-HTTPS Redirection**: Automatically redirects plain HTTP requests on port 80 to the canonical HTTPS service with `301 Moved Permanently`.
- **ACME Challenge Exemption**: Preserves HTTP-01 challenge paths (`/.well-known/acme-challenge/*`) on port 80 to guarantee seamless certificate issuance without redirection loops.
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

### 2. Run with Let's Encrypt (Default Production Mode)

Using the `start.sh` helper script:
```bash
sudo ./start.sh --hostname part.salikh.info --backend http://192.168.1.11:8080 --verbose
```

Or running the binary directly:
```bash
sudo ./https-proxy --hostname part.salikh.info --backend http://192.168.1.11:8080 --verbose
```

> **Note**: Binding to standard privileged ports 80 and 443 requires root privileges (`sudo`) or the `CAP_NET_BIND_SERVICE` Linux capability (`sudo setcap 'cap_net_bind_service=+ep' ./https-proxy`).

### 3. Run with Self-Signed Certificates (Local Development / Testing)

```bash
# Generate self-signed cert for testing
./generate-self-signed-cert.sh --hostname myserver.local --output-dir ./certs

# Run proxy in self-signed mode
sudo ./start.sh --hostname myserver.local --backend http://192.168.1.11:8080 --self-signed --self-signed-dir ./certs
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
```

For the complete flag matrix and detailed parameter rules, see [**CLI Reference**](docs/cli-reference.md).

---

## Detailed Documentation

Comprehensive documentation of design decisions, architecture, and deployment setup can be found in the [`docs/`](docs/) directory:

- [**CLI Reference**](docs/cli-reference.md): Detailed matrix of all flags, default values, requirements, and invocation examples.
- [**Architecture & Proxy Pipeline**](docs/architecture.md): Overview of request processing, reverse proxy director, header transformations, and graceful shutdown.
- [**HTTP Redirection & ACME Challenges**](docs/redirect-and-acme.md): Deep dive into the HTTP-to-HTTPS redirect logic, ACME HTTP-01 challenge exemption, LAN IP canonicalization, and SNI fallback mechanisms.
- [**Certificate Management Modes**](docs/certificates.md): Let's Encrypt lifecycle, self-signed certificates, and manual certificate configuration.
- [**Networking, IPv6, and Firewall Setup**](docs/deployment-and-firewall.md): Dual-stack IPv4/IPv6 routing, Let's Encrypt reachability, `ip6tables`/`iptables` rules, and persistent Debian configuration.
