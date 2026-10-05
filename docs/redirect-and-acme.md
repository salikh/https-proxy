# HTTP Redirection & ACME Challenge Mechanics

This document explains the design, protocol interactions, and non-obvious engineering decisions behind the plain HTTP listener (port 80) and its interaction with Let's Encrypt (ACME).

---

## 1. Dual Role of Port 80

In HTTPS mode, the proxy binds to two ports:
- **Port 443**: The primary secure listener serving application traffic via TLS.
- **Port 80**: A dual-purpose auxiliary listener responsible for:
  1. Answering automated ACME HTTP-01 challenges for domain validation.
  2. Redirecting all incoming plain HTTP web traffic to HTTPS.

---

## 2. ACME HTTP-01 Challenge Exemption

### The Challenge Protocol
When Let's Encrypt provisions or renews a TLS certificate for a domain (e.g., `example.com`), it validates domain ownership by issuing an **HTTP-01 challenge** (RFC 8555, Section 8.3):
1. Let's Encrypt asks the proxy for a token response.
2. Let's Encrypt's validation servers connect to `http://<domain>:80/.well-known/acme-challenge/<token>`.
3. The server must reply over plain HTTP with HTTP status `200 OK` and the key authorization token.

### Why ACME Challenges Must NOT Be Redirected
If port 80 unconditionally redirects all traffic to HTTPS, validation servers may encounter TLS errors (e.g. if the certificate is not yet issued or expired), causing domain validation to fail.

### Implementation Architecture
In `proxy.go`:
```go
func (p *HTTPSProxy) serveHTTP(listener net.Listener) error {
    var handler http.Handler

    if acmeMgr, ok := p.certManager.(*autocert.Manager); ok {
        handler = acmeMgr.HTTPHandler(http.HandlerFunc(p.handleHTTP))
    } else {
        handler = http.HandlerFunc(p.handleHTTP)
    }

    p.httpServer = &http.Server{Handler: handler}
    return p.httpServer.Serve(listener)
}
```

1. **Let's Encrypt Mode**:
   `acmeMgr.HTTPHandler(...)` intercepts any incoming request starting with `/.well-known/acme-challenge/`. If the challenge token matches an active authorization, `autocert` handles the request directly and returns `200 OK`.
2. **Fallback Delegation**:
   Only requests that are **not** ACME challenges (or unknown/expired challenge tokens) are passed to `p.handleHTTP`.
3. **Explicit Guard in `handleHTTP`**:
   Even if `certManager` is nil (e.g., self-signed or manual cert mode) or an unrecognized challenge token reaches `handleHTTP`, the handler checks:
   ```go
   if isACMEChallenge(r) {
       http.NotFound(w, r)
       return
   }
   ```
   This guarantees that an ACME challenge request will **never** receive a `301 Redirect` to HTTPS.

---

## 3. Canonical Hostname vs. LAN IP Canonicalization

### The Bug / Challenge
When deploying this proxy on a server or gateway router (e.g. at IP `192.168.1.1`):
1. A client on the local network visits `http://192.168.1.1/` in their web browser.
2. The HTTP request arrives with `Host: 192.168.1.1`.
3. If the redirect logic naively preserves `r.Host`, it replies:
   ```http
   HTTP/1.1 301 Moved Permanently
   Location: https://192.168.1.1/
   ```
4. The browser follows the redirect to `https://192.168.1.1:443`.
5. **The Failure**:
   - Clients connecting to raw IP addresses over TLS **do not send an SNI (Server Name Indication) extension** (RFC 6066 explicitly forbids IP literals in the `HostName` field).
   - `autocert.Manager.GetCertificate` checks `if hello.ServerName == ""` and immediately fails the handshake with:
     ```
     acme/autocert: missing server name
     ```
   - Furthermore, Let's Encrypt cannot issue public certificates for private RFC 1918 IP addresses (`192.168.1.1`).
   - Even if a certificate were returned, the client's browser would reject it due to a domain mismatch error (`example.com` != `192.168.1.1`).

### The Solution: Prioritize Configured Hostname
In `redirectTarget`:
```go
hostname := p.defaultHostname
if hostname == "" {
    hostname = r.Host
    if h, _, err := net.SplitHostPort(hostname); err == nil {
        hostname = h
    }
}
```

Whenever `--hostname` is configured on the proxy (e.g. `example.com`), **all plain HTTP requests—whether addressed to `192.168.1.1`, `localhost`, or the domain—are redirected to the canonical domain**:
```http
HTTP/1.1 301 Moved Permanently
Location: https://example.com/
```
When the client follows this redirect:
1. The client looks up `example.com`.
2. Connects to `https://example.com/`.
3. Transmits `ServerName: example.com` in the TLS ClientHello SNI.
4. `autocert` provisions or retrieves the valid certificate, and the TLS handshake succeeds seamlessly.

---

## 4. SNI Fallback in `ServeTLS`

If a client or automated tool connects directly to the HTTPS port without SNI (for instance, `curl -k https://192.168.1.1/` or an IP health-checker):
- Standard `autocert` behavior is to abort the TLS handshake with `acme/autocert: missing server name`.
- In `ServeTLS`, the proxy wraps `GetCertificate`:
```go
tlsConfig := certManager.TLSConfig()
origGetCertificate := tlsConfig.GetCertificate
tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    if hello.ServerName == "" && p.defaultHostname != "" {
        helloCopy := *hello
        helloCopy.ServerName = p.defaultHostname
        return origGetCertificate(&helloCopy)
    }
    return origGetCertificate(hello)
}
```
If `hello.ServerName` is empty, the proxy injects `p.defaultHostname`. This allows `autocert` to return the certificate for the configured domain rather than terminating the connection with a TLS handshake error.

---

## 5. Port Handling and IPv6 Address Formatting

The URL constructor in `redirectTarget` accounts for non-standard HTTPS ports and IPv6 literals:

1. **Standard HTTPS Port (443)**:
   - Port 443 is omitted from the redirect URL (e.g., `https://example.com/path`).
2. **Custom HTTPS Port (e.g., 8443)**:
   - Handled via `net.JoinHostPort(cleanHost, fmt.Sprintf("%d", httpsPort))`, producing `https://example.com:8443/path`.
3. **IPv6 Address Formatting**:
   - Bare IPv6 addresses containing colons (e.g., `::1`) are enclosed in brackets (`[::1]`) so that the resulting URL `https://[::1]/path` complies with RFC 3986 URI syntax.
