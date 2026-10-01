package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// HeaderTransformer is a function that modifies request headers before forwarding to the backend.
// This is an extension point for future multi-backend routing and header rewriting.
type HeaderTransformer func(r *http.Request, target *url.URL) error

// HTTPSProxy wraps the reverse proxy with certificate management and header transformation.
type HTTPSProxy struct {
	backend           *url.URL
	virtualHosts      map[string]*url.URL // hostname -> backend URL mapping
	reverseProxy      *httputil.ReverseProxy
	certManager       interface{} // *autocert.Manager or nil
	httpServer        *http.Server
	httpsServer       *http.Server
	headerTransformer HeaderTransformer
	verbose           bool
	httpsPort         int
	defaultHostname   string
	oauthManager      *OAuthManager
}

// NewHTTPSProxy creates a new HTTPS proxy instance.
func NewHTTPSProxy(backend *url.URL, certManager interface{}, verbose bool) *HTTPSProxy {
	proxy := &HTTPSProxy{
		backend:     backend,
		certManager: certManager,
		verbose:     verbose,
		httpsPort:   443,
	}

	// Set up the reverse proxy with custom director to transform headers
	proxy.reverseProxy = &httputil.ReverseProxy{
		Director: proxy.director,
		ModifyResponse: func(r *http.Response) error {
			if proxy.verbose {
				log.Printf("[response] Status: %d, Content-Length: %d", r.StatusCode, r.ContentLength)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Backend error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Set up header transformer (can be overridden for custom logic)
	proxy.headerTransformer = defaultHeaderTransformer

	return proxy
}

// getBackendForRequest returns the backend URL for the given request.
// If virtual hosts are configured, it selects based on the Host header.
// Otherwise, it returns the default backend.
func (p *HTTPSProxy) getBackendForRequest(r *http.Request) *url.URL {
	if len(p.virtualHosts) > 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)

		if backend, ok := p.virtualHosts[host]; ok {
			return backend
		}

		if p.verbose {
			log.Printf("[request] No virtual host configured for %q, using default backend", host)
		}
	}

	return p.backend
}

// getHostnameForRequest returns the hostname to use for OAuth and redirects.
// If virtual hosts are configured and the request's hostname matches one, that hostname is used.
// Otherwise, the default hostname is returned.
func (p *HTTPSProxy) getHostnameForRequest(r *http.Request) string {
	if len(p.virtualHosts) > 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)

		if _, ok := p.virtualHosts[host]; ok {
			return host
		}
	}

	return p.defaultHostname
}

// director modifies the request before sending it to the backend.
func (p *HTTPSProxy) director(r *http.Request) {
	if p.verbose {
		log.Printf("[request] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
	}

	backend := p.getBackendForRequest(r)

	// Rewrite the request to target the backend
	r.URL.Scheme = backend.Scheme
	r.URL.Host = backend.Host
	if backend.Path != "" {
		r.URL.Path = backend.Path + r.URL.Path
	}

	// Apply header transformation
	if err := p.headerTransformer(r, backend); err != nil {
		log.Printf("Header transformation error: %v", err)
	}

	// Clear request host to match the backend
	r.RequestURI = ""
	r.Host = backend.Host
}

// defaultHeaderTransformer handles standard header transformations.
// This is the extension point for future multi-backend routing logic.
func defaultHeaderTransformer(r *http.Request, target *url.URL) error {
	// Remove hop-by-hop headers that should not be forwarded
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopByHopHeaders {
		r.Header.Del(header)
	}

	// Add X-Forwarded-For if not already present
	if r.Header.Get("X-Forwarded-For") == "" {
		r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	}

	// Add X-Forwarded-Proto
	r.Header.Set("X-Forwarded-Proto", "https")

	// Add X-Forwarded-Host to preserve the original host
	if r.Header.Get("X-Forwarded-Host") == "" {
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	}

	return nil
}

// SetHTTPSPort sets the HTTPS port to redirect to when not using default port 443.
func (p *HTTPSProxy) SetHTTPSPort(port int) {
	p.httpsPort = port
}

// SetDefaultHostname sets the default hostname to redirect to if the request does not provide a Host header.
func (p *HTTPSProxy) SetDefaultHostname(hostname string) {
	p.defaultHostname = hostname
}

// SetOAuthManager configures OAuth authentication for the HTTPS proxy.
func (p *HTTPSProxy) SetOAuthManager(mgr *OAuthManager) {
	p.oauthManager = mgr
}

// SetVirtualHosts configures virtual host routing for the HTTPS proxy.
func (p *HTTPSProxy) SetVirtualHosts(virtualHosts map[string]*url.URL) {
	p.virtualHosts = virtualHosts
}

// isACMEChallenge checks if the HTTP request is an ACME HTTP-01 challenge verification request.
func isACMEChallenge(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") || r.URL.Path == "/.well-known/acme-challenge"
}

// redirectTarget builds the target HTTPS URL for an incoming HTTP request.
func (p *HTTPSProxy) redirectTarget(r *http.Request) (string, error) {
	// Extract hostname from request (without port)
	requestHost := r.Host
	requestHostname := requestHost
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		requestHostname = h
	}

	// If virtual hosts are configured, check if the incoming hostname matches one
	hostname := ""
	if len(p.virtualHosts) > 0 {
		if _, ok := p.virtualHosts[strings.ToLower(requestHostname)]; ok {
			// Request hostname matches a virtual host, use it
			hostname = requestHostname
		}
	}

	// If no virtual host match or no virtual hosts configured, use default hostname
	if hostname == "" {
		hostname = p.defaultHostname
		if hostname == "" {
			// If no default, try using the request hostname (fallback)
			hostname = requestHostname
		}
	}

	if hostname == "" {
		return "", fmt.Errorf("missing Host header")
	}

	cleanHost := strings.Trim(hostname, "[]")

	httpsPort := p.httpsPort
	if httpsPort <= 0 {
		httpsPort = 443
	}

	var targetHost string
	if httpsPort == 443 {
		if strings.Contains(cleanHost, ":") {
			targetHost = "[" + cleanHost + "]"
		} else {
			targetHost = cleanHost
		}
	} else {
		targetHost = net.JoinHostPort(cleanHost, fmt.Sprintf("%d", httpsPort))
	}

	uri := r.URL.RequestURI()
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}

	return "https://" + targetHost + uri, nil
}

// ServeHTTP handles HTTP requests (ACME challenges and HTTPS redirection).
func (p *HTTPSProxy) ServeHTTP(listener net.Listener) error {
	return p.serveHTTP(listener)
}

// serveHTTP handles HTTP requests (ACME challenges and HTTPS redirection).
func (p *HTTPSProxy) serveHTTP(listener net.Listener) error {
	var handler http.Handler

	// Use ACME challenge handler if we have an autocert manager
	if acmeMgr, ok := p.certManager.(*autocert.Manager); ok {
		handler = acmeMgr.HTTPHandler(http.HandlerFunc(p.handleHTTP))
	} else {
		// No ACME manager, use fallback handler directly
		handler = http.HandlerFunc(p.handleHTTP)
	}

	p.httpServer = &http.Server{
		Handler: handler,
	}
	return p.httpServer.Serve(listener)
}

// handleHTTP handles HTTP requests, redirecting them to HTTPS except for ACME challenge requests.
func (p *HTTPSProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.verbose {
		log.Printf("[http] %s %s from %s", r.Method, sanitizeURI(r.RequestURI), r.RemoteAddr)
	}

	// Do not redirect ACME challenge requests
	if isACMEChallenge(r) {
		if p.verbose {
			log.Printf("[http] ACME challenge request not handled by cert manager: %s", r.URL.Path)
		}
		http.NotFound(w, r)
		return
	}

	targetURL, err := p.redirectTarget(r)
	if err != nil {
		if p.verbose {
			log.Printf("[http] Redirect error: %v", err)
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if p.verbose {
		log.Printf("[http] Redirecting %s to %s", sanitizeURI(r.RequestURI), sanitizeURI(targetURL))
	}

	http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
}

// ServeTLS starts the HTTPS server with Let's Encrypt certificates.
func (p *HTTPSProxy) ServeTLS(listener net.Listener, certManager *autocert.Manager) error {
	tlsConfig := certManager.TLSConfig()
	origGetCertificate := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// If a client connects directly to HTTPS without SNI (e.g. connecting via IP address),
		// fall back to defaultHostname instead of failing with "acme/autocert: missing server name".
		if hello.ServerName == "" && p.defaultHostname != "" {
			helloCopy := *hello
			helloCopy.ServerName = p.defaultHostname
			return origGetCertificate(&helloCopy)
		}
		return origGetCertificate(hello)
	}

	p.httpsServer = &http.Server{
		Addr:      listener.Addr().String(),
		Handler:   http.HandlerFunc(p.serveProxy),
		TLSConfig: tlsConfig,
	}

	return p.httpsServer.ServeTLS(listener, "", "")
}

// ServeTLSWithFiles starts the HTTPS server with manually specified certificate files.
func (p *HTTPSProxy) ServeTLSWithFiles(listener net.Listener, certFile, keyFile string) error {
	p.httpsServer = &http.Server{
		Addr:    listener.Addr().String(),
		Handler: http.HandlerFunc(p.serveProxy),
	}

	return p.httpsServer.ServeTLS(listener, certFile, keyFile)
}

// serveProxy handles HTTPS requests by forwarding them to the backend.
func (p *HTTPSProxy) serveProxy(w http.ResponseWriter, r *http.Request) {
	if p.verbose {
		log.Printf("[https] %s %s from %s", r.Method, sanitizeURI(r.RequestURI), r.RemoteAddr)
	}

	// ACME challenge exemption: NEVER require OAuth for ACME challenges
	if isACMEChallenge(r) {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// OAuth authentication enforcement
	if p.oauthManager != nil {
		if p.oauthManager.IsCallback(r) {
			p.oauthManager.HandleCallback(w, r)
			return
		}
		if p.oauthManager.IsLogout(r) {
			p.oauthManager.HandleLogout(w, r)
			return
		}

		user, err := p.oauthManager.AuthenticateRequest(r)
		if err != nil {
			if p.verbose {
				log.Printf("[oauth] Unauthenticated request for %s, redirecting to login", sanitizeURI(r.RequestURI))
			}
			p.oauthManager.HandleLoginRedirect(w, r)
			return
		}

		// Inject authenticated identity headers for backend
		r.Header.Set("X-Forwarded-User", user)
		r.Header.Set("X-Auth-Email", user)
	}

	p.reverseProxy.ServeHTTP(w, r)
}

// Shutdown gracefully shuts down the HTTP and HTTPS servers.
func (p *HTTPSProxy) Shutdown(ctx context.Context) error {
	var errs []string

	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("HTTP server shutdown error: %v", err))
		}
	}

	if p.httpsServer != nil {
		if err := p.httpsServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("HTTPS server shutdown error: %v", err))
		}
	}

	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		log.Printf("Shutdown errors: %s", msg)
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// HTTPProxy is a plain HTTP proxy (no TLS).
type HTTPProxy struct {
	backend           *url.URL
	virtualHosts      map[string]*url.URL // hostname -> backend URL mapping
	reverseProxy      *httputil.ReverseProxy
	httpServer        *http.Server
	headerTransformer HeaderTransformer
	verbose           bool
	oauthManager      *OAuthManager
}

// NewHTTPProxy creates a new HTTP proxy instance.
func NewHTTPProxy(backend *url.URL, verbose bool) *HTTPProxy {
	proxy := &HTTPProxy{
		backend: backend,
		verbose: verbose,
	}

	// Set up the reverse proxy with custom director to transform headers
	proxy.reverseProxy = &httputil.ReverseProxy{
		Director: proxy.director,
		ModifyResponse: func(r *http.Response) error {
			if proxy.verbose {
				log.Printf("[response] Status: %d, Content-Length: %d", r.StatusCode, r.ContentLength)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Backend error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Set up header transformer
	proxy.headerTransformer = defaultHeaderTransformer

	return proxy
}

// getBackendForRequest returns the backend URL for the given request.
// If virtual hosts are configured, it selects based on the Host header.
// Otherwise, it returns the default backend.
func (p *HTTPProxy) getBackendForRequest(r *http.Request) *url.URL {
	if len(p.virtualHosts) > 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)

		if backend, ok := p.virtualHosts[host]; ok {
			return backend
		}

		if p.verbose {
			log.Printf("[request] No virtual host configured for %q, using default backend", host)
		}
	}

	return p.backend
}

// director modifies the request before sending it to the backend.
func (p *HTTPProxy) director(r *http.Request) {
	if p.verbose {
		log.Printf("[request] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
	}

	backend := p.getBackendForRequest(r)

	// Rewrite the request to target the backend
	r.URL.Scheme = backend.Scheme
	r.URL.Host = backend.Host
	if backend.Path != "" {
		r.URL.Path = backend.Path + r.URL.Path
	}

	// Apply header transformation
	if err := p.headerTransformer(r, backend); err != nil {
		log.Printf("Header transformation error: %v", err)
	}

	// Clear request host to match the backend
	r.RequestURI = ""
	r.Host = backend.Host
}

// SetOAuthManager configures OAuth authentication for the HTTP proxy.
func (p *HTTPProxy) SetOAuthManager(mgr *OAuthManager) {
	p.oauthManager = mgr
}

// SetVirtualHosts configures virtual host routing for the HTTP proxy.
func (p *HTTPProxy) SetVirtualHosts(virtualHosts map[string]*url.URL) {
	p.virtualHosts = virtualHosts
}

// ServeHTTP starts the HTTP server.
func (p *HTTPProxy) ServeHTTP(listener net.Listener) error {
	p.httpServer = &http.Server{
		Addr:    listener.Addr().String(),
		Handler: http.HandlerFunc(p.serveProxy),
	}

	return p.httpServer.Serve(listener)
}

// serveProxy handles HTTP requests by forwarding them to the backend.
func (p *HTTPProxy) serveProxy(w http.ResponseWriter, r *http.Request) {
	if p.verbose {
		log.Printf("[http] %s %s from %s", r.Method, sanitizeURI(r.RequestURI), r.RemoteAddr)
	}

	// ACME challenge exemption: NEVER require OAuth for ACME challenges
	if isACMEChallenge(r) {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// OAuth authentication enforcement
	if p.oauthManager != nil {
		if p.oauthManager.IsCallback(r) {
			p.oauthManager.HandleCallback(w, r)
			return
		}
		if p.oauthManager.IsLogout(r) {
			p.oauthManager.HandleLogout(w, r)
			return
		}

		user, err := p.oauthManager.AuthenticateRequest(r)
		if err != nil {
			if p.verbose {
				log.Printf("[oauth] Unauthenticated request for %s, redirecting to login", sanitizeURI(r.RequestURI))
			}
			p.oauthManager.HandleLoginRedirect(w, r)
			return
		}

		// Inject authenticated identity headers for backend
		r.Header.Set("X-Forwarded-User", user)
		r.Header.Set("X-Auth-Email", user)
	}

	p.reverseProxy.ServeHTTP(w, r)
}

// Shutdown gracefully shuts down the HTTP server.
func (p *HTTPProxy) Shutdown(ctx context.Context) error {
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
			return err
		}
	}
	return nil
}
