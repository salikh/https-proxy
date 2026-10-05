# Google OAuth 2.0 Authentication & Secret Protection

This document details the OAuth 2.0 authentication architecture, ACME challenge exemption mechanics, access control whitelist, and multi-layered defense strategy for protecting OAuth client secrets in `https-proxy`.

---

## 1. Overview & Architecture

When OAuth enforcement is enabled via the `--oauth` flag, the reverse proxy sits in front of your upstream HTTP application and acts as an authentication gateway.

```
                           +---------------------------------------+
                           |              https-proxy              |
                           +---------------------------------------+
                                              |
Incoming Request                             |
-------------------------------------------->|
                                              |
[Path == /.well-known/acme-challenge/* ?] ----+--> YES: Bypass OAuth! Serve Challenge (200 / autocert)
                                              |
[Path == /callback ?] ------------------------+--> YES: Verify CSRF State, Exchange Code, Set Cookie,
                                              |         Redirect to Destination URL
                                              |
[Valid HMAC-Signed Session Cookie ?] ---------+--> YES: Inject X-Forwarded-User & X-Auth-Email Headers,
                                              |         Forward Request to Backend
                                              |
                                              +--> NO:  Save Destination URI, Generate CSRF State,
                                                        Redirect (302) to Google OAuth Login
```

### Key Properties:
1. **Universal Enforcement**: All HTTP/HTTPS requests to the backend require valid OAuth authentication.
2. **ACME Challenge Exemption**: ACME HTTP-01 challenge paths (`/.well-known/acme-challenge/*`) are **strictly exempt** from OAuth authentication on both port 80 and port 443, ensuring automated Let's Encrypt certificate issuance and renewal never fail.
3. **Transparent Identity Forwarding**: After successful login, the proxy injects `X-Forwarded-User` and `X-Auth-Email` headers containing the verified user email address so the backend service knows the authenticated identity without needing to interact with Google APIs.

---

## 2. Configuration & Setup

### Google Cloud Console Setup (`secret.json`)
The proxy uses the standard Google Cloud Console Web Application credentials JSON file (`secret.json`), containing:
```json
{
  "web": {
    "client_id": "1234567890123-....apps.googleusercontent.com",
    "project_id": "...",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_secret": "GOCSPX-...",
    "redirect_uris": [
      "https://example.com.info/callback"
    ],
    "javascript_origins": [
      "https://example.com"
    ]
  }
}
```

- The redirect URI callback path (e.g. `/callback`) is automatically extracted from `redirect_uris`.

### Access Whitelist (`allowed.txt`)
Access can be restricted to specific email addresses or domains:
- By default, if an `allowed.txt` file exists in the working directory, the proxy automatically loads the email whitelist from it.
- Format: One email address per line. Comments starting with `#` and blank lines are ignored:
  ```text
  # Authorized Admin Users
  me@example.com
  me@example.info
  you@gmail.com
  ```
- Additional users or files can be configured via:
  - `--oauth-allowed-file <path>`: Load emails from an alternative file.
  - `--oauth-allowed-users <email1,email2>`: Comma-separated list of allowed emails.
  - `--oauth-allowed-domains <domain1,domain2>`: Allow any authenticated Google user from specified domains (e.g. `example.com`).

---

## 3. Protecting OAuth Client Secrets

OAuth client secrets grant the ability to exchange authorization codes and impersonate your application. To defend against leakage, accidental exposure, and unauthorized access, `https-proxy` implements a defense-in-depth security model:

### Layer 1: Version Control & Repository Isolation
- `.gitignore` explicitly excludes all credentials and secret variants:
  ```gitignore
  /secret.json
  *secret*.json
  *.secret.json
  client_secret*.json
  *.enc
  ```
- Jujutsu (`jj`) and Git automatically ignore these patterns, preventing accidental commits to public or internal code repositories.

### Layer 2: Automatic File Permission Lockdown (0600)
- On startup, `LoadOAuthSecret` inspects file permissions (`os.Stat`).
- If the secret file is readable by group or other users (`mode & 0077 != 0`, e.g. standard `0644`), the proxy **automatically tightens permissions to `0600`** (`chmod 0600`), ensuring only the owner process can read or write the file.
- A security audit log is emitted notifying the operator that permissions were tightened.

### Layer 3: Authenticated Encryption at Rest (AES-256-GCM)
- Plaintext secrets on disk can be encrypted into an authenticated AES-256-GCM container (`secret.json.enc`).
- **Cryptographic Details**:
  - Key derivation: PBKDF2 with SHA-256, 100,000 iterations, and a 16-byte cryptographically secure random salt.
  - Encryption: AES-256-GCM with a 12-byte random nonce and authenticated header data (AAD).
- **Encrypting Secrets**:
  Use the provided script or CLI flag:
  ```bash
  ./encrypt-secret.sh secret.json secret.json.enc
  ```
  Or directly:
  ```bash
  ./https-proxy -encrypt-secret secret.json -encrypt-secret-out secret.json.enc
  ```
  Once encrypted, the plaintext `secret.json` can be safely deleted or moved to offline cold storage!
- **Running with Encrypted Secrets**:
  The passphrase can be supplied securely via:
  - Environment variable: `export OAUTH_PASSPHRASE="your-passphrase"`
  - CLI flag: `--oauth-passphrase="your-passphrase"`
  - Interactive terminal prompt (hidden input without echo via `golang.org/x/term`).

### Layer 4: Zero-Disk Deployment (Environment Variable Injection)
- In cloud and containerized environments (Kubernetes, Docker, Google Cloud Run), secrets should not be stored on persistent disk.
- Setting the `OAUTH_SECRET_JSON` environment variable allows `https-proxy` to read credentials directly from memory:
  ```bash
  export OAUTH_SECRET_JSON='{"web":{"client_id":"...","client_secret":"..."}}'
  ./https-proxy --oauth --hostname example.com --backend http://localhost:8080
  ```
  No secret file ever touches the filesystem.

### Layer 5: Runtime Memory & Log Sanitization
- The `client_secret` is never printed to logs or standard output.
- When `--verbose` logging is active:
  - URLs and query parameters are filtered through `sanitizeURI()`.
  - Sensitive parameters (`code`, `state`, `client_secret`, `access_token`, `refresh_token`) are automatically redacted to `[REDACTED]`.
  - Upstream reverse proxy strips internal cookies and hop-by-hop credentials.

### Layer 6: Cryptographic Session Cookies & CSRF Protection
- **Tamper-Proof Session Cookie (`_proxy_session`)**:
  - Derived using HMAC-SHA256 with a 256-bit key derived from the client secret (`https-proxy-cookie-secret-v1`).
  - Cookie attributes: `HttpOnly` (blocks JavaScript XSS access), `Secure` (only transmitted over HTTPS), `SameSite=Lax` (blocks cross-site request forgery).
  - Contains expiration timestamp verified on every incoming request.
- **CSRF State Token (`_proxy_oauth_state`)**:
  - A cryptographically random 256-bit state token is generated on login redirect.
  - Tied to a signed, short-lived (10-minute) state cookie.
  - Mitigates OAuth login CSRF and open redirect attacks (destination URLs are strictly sanitized to relative paths).

---

## 4. Usage Recipes

### 1. Production Mode with Let's Encrypt & OAuth
Using `start.sh`:
```bash
sudo ./start.sh \
  --hostname example.com \
  --backend http://192.168.1.11:8080 \
  --oauth \
  --verbose
```

### 2. Encrypted Secret with Passphrase
```bash
# 1. Encrypt secret
./encrypt-secret.sh secret.json secret.json.enc
rm secret.json

# 2. Run with encrypted secret
export OAUTH_PASSPHRASE="SecretPassphrase123"
sudo ./start.sh \
  --hostname example.com \
  --backend http://192.168.1.11:8080 \
  --oauth \
  --oauth-secret secret.json.enc
```

### 3. Custom Whitelist File
```bash
sudo ./start.sh \
  --hostname example.com \
  --backend http://192.168.1.11:8080 \
  --oauth \
  --oauth-allowed-file /etc/proxy/admins.txt
```
