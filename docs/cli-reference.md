# Command-Line Interface (CLI) Reference

This document provides a complete reference for all command-line flags accepted by the `https-proxy` binary and the `start.sh` helper script.

---

## 1. Quick Flag Matrix

| Flag | Type | Default | Required? | Modes Applicable | Description |
|---|---|---|---|---|---|
| `--backend` | `string` | `""` | **Yes** | All | Upstream backend URL (`http://` or `https://`) |
| `--hostname` | `string` | `""` | **Yes** (HTTPS mode) | HTTPS (Let's Encrypt, Self-Signed, Manual) | Domain name of the proxy service |
| `--port` | `int` | `443` | No | HTTPS | TCP port to listen on for HTTPS traffic |
| `--http-port` | `int` | `80` | No | All | TCP port for HTTP challenges, redirects, or plain HTTP |
| `--cache-dir` | `string` | `~/.cache/https-proxy` | No | Let's Encrypt | Storage directory for ACME keys and certificates |
| `--self-signed` | `bool` | `false` | No | Self-Signed | Use self-signed certs instead of Let's Encrypt |
| `--self-signed-dir` | `string` | `~/.cache/https-proxy-selfsigned` | No | Self-Signed | Directory containing `cert.pem` and `key.pem` |
| `--cert` | `string` | `""` | No | Manual Cert | Path to X.509 certificate file |
| `--key` | `string` | `""` | No | Manual Cert | Path to matching private key file |
| `--no-tls` | `bool` | `false` | No | Plain HTTP | Run as plain HTTP proxy without TLS or redirection |
| `--verbose` | `bool` | `false` | No | All | Enable detailed logging of requests and responses |
| `--oauth` | `bool` | `false` | No | All | Enforce Google OAuth authentication on all requests (except ACME) |
| `--oauth-secret` | `string` | `secret.json` | No | OAuth | Path to plaintext or encrypted `.enc` credentials JSON |
| `--oauth-passphrase` | `string` | `""` | No | OAuth | Passphrase for encrypted secret file (or `OAUTH_PASSPHRASE` env var) |
| `--oauth-allowed-file` | `string` | `allowed.txt` | No | OAuth | Path to newline-delimited allowed user emails whitelist |
| `--oauth-allowed-users` | `string` | `""` | No | OAuth | Comma-separated list of allowed user emails |
| `--oauth-allowed-domains` | `string` | `""` | No | OAuth | Comma-separated list of allowed email domains |
| `--encrypt-secret` | `string` | `""` | No | CLI Utility | Path to plaintext secret file to encrypt with AES-256-GCM and exit |
| `--encrypt-secret-out` | `string` | `input.enc` | No | CLI Utility | Destination path for encrypted secret file |

---

## 2. Detailed Flag Descriptions

### `--backend <URL>`
- **Type**: String
- **Required**: Yes (all modes)
- **Description**: Specifies the destination server to which requests are forwarded.
- **Rules**:
  - Must include protocol scheme (`http://` or `https://`).
  - May include optional path prefix (e.g. `http://192.168.1.11:8080/v1`). Path prefixes will be prepended to incoming request paths.
- **Example**: `--backend http://192.168.1.11:8080`

### `--hostname <HOSTNAME>`
- **Type**: String
- **Required**: Yes, in HTTPS mode (default). Optional only when `--no-tls` is set.
- **Description**: The canonical domain name for this proxy.
- **Rules**:
  - Must match the public DNS name pointing to this server.
  - In Let's Encrypt mode, certificate issuance is strictly whitelisted to this domain.
  - Used as the target host for automatic HTTP-to-HTTPS redirects, canonicalizing requests originating from LAN IP addresses or `localhost`.
- **Example**: `--hostname part.salikh.info`

### `--port <PORT>`
- **Type**: Integer
- **Default**: `443`
- **Description**: The TCP port for incoming HTTPS connections.
- **Notes**:
  - Binding to ports < 1024 requires root privileges (`sudo`) or `CAP_NET_BIND_SERVICE`.
  - If a non-standard port is specified (e.g. `8443`), HTTP redirects will include the port in the `Location` header (`https://part.salikh.info:8443/`).
- **Example**: `--port 8443`

### `--http-port <PORT>`
- **Type**: Integer
- **Default**: `80`
- **Description**: 
  - **In HTTPS mode**: The port that listens for ACME HTTP-01 challenges and redirects all other HTTP traffic to HTTPS.
  - **In `--no-tls` mode**: The primary proxy listening port.
- **Example**: `--http-port 8080`

### `--cache-dir <DIR>`
- **Type**: String
- **Default**: `$HOME/.cache/https-proxy`
- **Description**: Directory where Let's Encrypt account keys and issued certificates are cached.
- **Notes**:
  - Automatically created with permissions `0700` if it does not exist.
  - Caching prevents hitting Let's Encrypt rate limits on proxy restarts.
- **Example**: `--cache-dir /var/cache/https-proxy`

### `--self-signed`
- **Type**: Boolean flag (no value required)
- **Default**: `false`
- **Description**: Disables Let's Encrypt and loads self-signed certificates from `--self-signed-dir`.
- **Requires**: The files `cert.pem` and `key.pem` must exist in the target directory (generated via `generate-self-signed-cert.sh`).

### `--self-signed-dir <DIR>`
- **Type**: String
- **Default**: `$HOME/.cache/https-proxy-selfsigned`
- **Description**: Directory path containing `cert.pem` and `key.pem` for self-signed mode.
- **Example**: `--self-signed-dir ./certs`

### `--cert <FILE>` and `--key <FILE>`
- **Type**: Strings (file paths)
- **Description**: Path to manually managed X.509 certificate and private key files.
- **Rules**: Both flags must be provided together.
- **Example**: `--cert /etc/ssl/certs/site.crt --key /etc/ssl/private/site.key`

### `--no-tls`
- **Type**: Boolean flag
- **Default**: `false`
- **Description**: Disables HTTPS and ACME challenge logic. Runs purely as an HTTP reverse proxy on `--http-port`.
- **Notes**: `--hostname` is not required when `--no-tls` is active.

### `--verbose`
- **Type**: Boolean flag
- **Default**: `false`
- **Description**: Enables request/response logging to stdout:
  - Inbound HTTP redirect logs (`[http] GET / from ... -> Redirecting to https://...`)
  - Inbound HTTPS request logs (`[https] GET /api from ...`)
  - Upstream backend response status and content-length (`[response] Status: 200, Content-Length: 1234`)
  - Sensitive parameters (`code`, `state`, `token`, `secret`) are automatically redacted.

### `--oauth`
- **Type**: Boolean flag
- **Default**: `false`
- **Description**: Enforces Google OAuth 2.0 authentication on all proxy requests (except ACME challenges). Unauthenticated visitors are redirected to Google login.

### `--oauth-secret <PATH>`
- **Type**: String (file path)
- **Default**: `secret.json`
- **Description**: Path to OAuth client credentials JSON (either plaintext or encrypted `.enc` file). Automatically tightens permissions to `0600` on startup.

### `--oauth-passphrase <PASSPHRASE>`
- **Type**: String
- **Default**: `""` (can also be supplied via `OAUTH_PASSPHRASE` environment variable or prompted interactively)
- **Description**: Passphrase to decrypt an AES-256-GCM encrypted OAuth secret file.

### `--oauth-allowed-file <PATH>`
- **Type**: String (file path)
- **Default**: `allowed.txt` (automatically loaded if file exists)
- **Description**: Path to a newline-delimited text file containing authorized Google user email addresses.

### `--oauth-allowed-users <EMAILS>`
- **Type**: String (comma-separated)
- **Default**: `""`
- **Description**: Additional authorized user email addresses (e.g. `salikh@gmail.com,salikh@google.com`).

### `--oauth-allowed-domains <DOMAINS>`
- **Type**: String (comma-separated)
- **Default**: `""`
- **Description**: Allowed Google Workspace email domains (e.g. `example.com`).

### `--encrypt-secret <PATH>`
- **Type**: String (file path)
- **Default**: `""`
- **Description**: CLI utility mode to encrypt a plaintext credentials file into an AES-256-GCM container (`.enc`) and immediately exit.

### `--encrypt-secret-out <PATH>`
- **Type**: String (file path)
- **Default**: `<input-path>.enc`
- **Description**: Destination path for the encrypted secret file when using `--encrypt-secret`.

---

## 3. Usage Examples

### Example A: Standard Production (Let's Encrypt)
```bash
sudo ./https-proxy \
  --hostname part.salikh.info \
  --backend http://192.168.1.11:8080 \
  --verbose
```

### Example B: Non-Standard Ports
Useful for running without root or behind external NAT port forwarders:
```bash
./https-proxy \
  --hostname part.salikh.info \
  --backend http://localhost:3000 \
  --port 8443 \
  --http-port 8080
```

### Example C: Self-Signed Testing
```bash
# 1. Generate certificates
./generate-self-signed-cert.sh --hostname dev.local --output-dir ./certs

# 2. Run proxy
sudo ./https-proxy \
  --hostname dev.local \
  --backend http://localhost:8080 \
  --self-signed \
  --self-signed-dir ./certs
```

### Example D: Manual Certificates (e.g., Certbot / Corporate PKI)
```bash
sudo ./https-proxy \
  --hostname api.example.com \
  --backend http://10.0.0.5:8000 \
  --cert /etc/letsencrypt/live/api.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/api.example.com/privkey.pem
```

### Example E: Plain HTTP Mode
```bash
./https-proxy \
  --backend http://localhost:9000 \
  --no-tls \
  --http-port 8080
```

### Example F: Enforcing OAuth Authentication with Allowed Users Whitelist
```bash
sudo ./https-proxy \
  --hostname part.salikh.info \
  --backend http://192.168.1.11:8080 \
  --oauth \
  --oauth-secret secret.json \
  --oauth-allowed-file allowed.txt
```

---

## 4. `start.sh` Wrapper Script

The repository includes a convenience wrapper script [`start.sh`](../start.sh) which:
1. Automatically runs `build.sh` if the `https-proxy` binary does not exist.
2. Accepts command line options and translates them into flags for `./https-proxy`.
3. Displays a formatted startup banner with the active configuration before launching.

```bash
./start.sh --hostname part.salikh.info --backend http://192.168.1.11:8080 --verbose
```
