# Architecture & Proxy Pipeline

This document describes the architectural structure and request handling pipeline of the `https-proxy` service.

---

## 1. High-Level Architecture

The service consists of two primary runtime modes implemented in Go using standard library components (`net/http`, `net/http/httputil`, `crypto/tls`) and `golang.org/x/crypto/acme/autocert`:

```
                       Internet / Clients
                               │
               ┌───────────────┴───────────────┐
               │                               │
        TCP Port 80 (HTTP)             TCP Port 443 (HTTPS)
               │                               │
    ┌──────────▼──────────┐         ┌──────────▼──────────┐
    │     HTTP Server     │         │    HTTPS Server     │
    │  (ACME & Redirect)  │         │  (Reverse Proxy)    │
    └──────────┬──────────┘         └──────────┬──────────┘
               │                               │
     /.well-known/acme-challenge/              │
     [Served by autocert]                      │
               │                               │
     All other paths                           │
     [301 Redirect to HTTPS]                   │
               │                               │
               └──────────────►────────────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │ ReverseProxy Engine │
                                    │ (Director & Headers)│
                                    └──────────┬──────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │   Backend Server    │
                                    │  (e.g., :8080)      │
                                    └─────────────────────┘
```

### Components

1. **`main.go`**:
   - Parses and validates CLI flags (`--hostname`, `--backend`, `--port`, `--http-port`, certificate flags).
   - Initializes certificate management (`*autocert.Manager`, manual cert paths, or self-signed cert paths).
   - Configures listeners, binds sockets, and registers signal hooks (`SIGINT`, `syscall.SIGTERM`).

2. **`HTTPSProxy` (`proxy.go`)**:
   - Manages the dual listeners: HTTP (port 80) for ACME challenges and redirection, and HTTPS (port 443) for TLS termination and reverse proxying.
   - Holds references to `backend *url.URL`, `reverseProxy *httputil.ReverseProxy`, and `certManager interface{}`.

3. **`HTTPProxy` (`proxy.go`)**:
   - Used only in `--no-tls` mode.
   - Runs a single HTTP listener forwarding requests directly to the backend without encryption.

---

## 2. Request Handling Pipeline

### HTTPS Request Flow (`serveProxy`)

1. **TLS Termination**:
   - Client establishes a TLS session with the HTTPS server.
   - In Let's Encrypt mode, TLS configuration is supplied by `certManager.TLSConfig()`, supporting HTTP/2 (`h2`) and TLS-ALPN challenge negotiation (`acme.ALPNProto`).
   - If ClientHello omits the SNI `ServerName` (e.g. direct IP connection), our wrapper injects `p.defaultHostname` to avoid handshake failure.

2. **Director Rewriting**:
   - The custom `ReverseProxy.Director` function rewrites the request:
     - `r.URL.Scheme` is set to `p.backend.Scheme` (`http` or `https`).
     - `r.URL.Host` is set to `p.backend.Host`.
     - Backend path prefixes are prepended if specified (e.g. `http://backend:8080/v1` + `/users` becomes `/v1/users`).
     - `r.Host` is updated to match `p.backend.Host`.
     - `r.RequestURI` is cleared (required by Go `http.Client`).

3. **Header Transformation**:
   - `HeaderTransformer` inspects and modifies headers before transmission to the backend.

4. **Response Forwarding**:
   - Upstream response status, headers, and body are streamed to the client.
   - In verbose mode (`--verbose`), request method, URI, remote client IP, and upstream HTTP status code and content length are logged.

5. **Error Handling**:
   - If the backend is unreachable or returns a dial error, `ErrorHandler` logs the error and returns `502 Bad Gateway` to the client.

---

## 3. Header Transformation Pipeline

The default transformer (`defaultHeaderTransformer`) implements standard reverse proxy safety mechanisms:

### A. Hop-by-Hop Header Stripping
Hop-by-hop headers are meaningful only for a single transport-level connection and must not be forwarded by proxies (RFC 2616 Section 13.5.1 / RFC 7230 Section 6.1):
- `Connection`
- `Keep-Alive`
- `Proxy-Authenticate`
- `Proxy-Authorization`
- `Te`
- `Trailers`
- `Transfer-Encoding`
- `Upgrade`

### B. Standard Forwarding Headers
- **`X-Forwarded-For`**: Set to `r.RemoteAddr` if not already present. If the client or an upstream edge proxy already set this header, the existing value is preserved.
- **`X-Forwarded-Proto`**: Set to `https` so the backend application knows the client communicated securely over TLS.
- **`X-Forwarded-Host`**: Set to the original `Host` header if not already present, ensuring backend URL generation (e.g., password reset links, OAuth callbacks) uses the public domain.

### Extension Point
The `HeaderTransformer` type is defined as:
```go
type HeaderTransformer func(r *http.Request, target *url.URL) error
```
Custom transformers can be plugged in for multi-backend routing, custom auth token forwarding, or custom header rewriting.

---

## 4. Graceful Shutdown

Both HTTP and HTTPS listeners register with a signal channel monitoring `os.Interrupt` and `syscall.SIGTERM`.

Upon receiving a shutdown signal:
1. Signal handler initiates a 30-second context timeout:
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
   defer cancel()
   ```
2. Calls `proxy.Shutdown(ctx)` which invokes `http.Server.Shutdown()` concurrently on both the HTTP and HTTPS instances.
3. Active connections are allowed to complete their in-flight requests while closing idle keep-alive connections.
4. If shutdown fails or times out, errors are logged before exiting with code 0.
