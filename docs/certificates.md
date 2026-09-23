# Certificate Management Modes

The `https-proxy` supports four operational modes for handling TLS certificates:

| Mode | Flag(s) | Primary Use Case |
|---|---|---|
| **Let's Encrypt** (Default) | *(none, default)* | Public-facing production deployments with automatic renewal |
| **Self-Signed** | `--self-signed`, `--self-signed-dir` | Local development, offline testing, internal staging |
| **Manual Files** | `--cert FILE`, `--key FILE` | Custom enterprise PKI, wildcard certs, Cloudflare origin certs |
| **Plain HTTP** | `--no-tls` | Internal container-to-container proxying or upstream TLS termination |

---

## 1. Let's Encrypt Automated Mode (Default)

In default mode, the proxy acts as an ACME client using `golang.org/x/crypto/acme/autocert`.

### Configuration Details
```go
certManager = &autocert.Manager{
    Prompt:      autocert.AcceptTOS,
    HostPolicy:  autocert.HostWhitelist(*hostname),
    Cache:       autocert.DirCache(*cacheDir),
}
```

- **Terms of Service**: Automatically agreed upon via `autocert.AcceptTOS`.
- **Host Whitelisting**: Restricted to the hostname passed via `--hostname`. This prevents denial-of-service or CA rate-limit exhaustion attacks where arbitrary clients request bogus certificates.
- **On-Disk Cache**: Stored in `~/.cache/https-proxy` (or `--cache-dir`). Directory is created with restricted permissions (`0700`).
- **Automatic Renewal**: `autocert` monitors certificate expiration and automatically triggers background renewal 30 days prior to expiration.
- **Zero-Downtime Reload**: Renewed certificates take effect immediately in memory without restarting the proxy process.

### Directory Structure of Cache
```text
~/.cache/https-proxy/
├── acme_account+key       # Account registration private key
└── part.salikh.info       # Concatenated cert and private key for the domain
```

---

## 2. Self-Signed Certificate Mode

Useful for local testing, LAN appliances, or environments without a public domain name.

### Step 1: Generate Certificate
Use the helper script [`generate-self-signed-cert.sh`](../generate-self-signed-cert.sh):

```bash
./generate-self-signed-cert.sh --hostname myserver.local --output-dir ./certs --days 365 --key-size 2048
```

This generates:
- `certs/key.pem`: RSA private key (2048-bit).
- `certs/cert.pem`: Self-signed X.509 certificate with Subject Alternative Name (`DNS:myserver.local`, `DNS:*.myserver.local`).

### Step 2: Run the Proxy
```bash
./start.sh --hostname myserver.local --backend http://127.0.0.1:8080 --self-signed --self-signed-dir ./certs
```

---

## 3. Manual Certificate Mode

When using certificates provided by an external authority (such as DigiCert, existing certbot installations, or Cloudflare Origin CA):

```bash
./start.sh \
  --hostname example.com \
  --backend http://127.0.0.1:8080 \
  --cert /etc/ssl/certs/example.com.crt \
  --key /etc/ssl/private/example.com.key
```

The proxy verifies that both files exist at startup and loads them using Go's `tls.LoadX509KeyPair`.

---

## 4. Plain HTTP Mode (`--no-tls`)

If TLS termination is performed upstream (e.g., by an AWS ALB or Cloudflare proxy) and `https-proxy` is only needed for header transformations and reverse proxying:

```bash
./start.sh --backend http://127.0.0.1:8080 --no-tls --http-port 8080
```

In this mode:
- No HTTPS listener is started.
- No HTTP-to-HTTPS redirect occurs.
- Traffic on `--http-port` is forwarded directly to the backend.
