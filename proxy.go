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
	reverseProxy      *httputil.ReverseProxy
	certManager       interface{} // *autocert.Manager or nil
	httpServer        *http.Server
	httpsServer       *http.Server
	headerTransformer HeaderTransformer
	verbose           bool
	httpsPort         int
	defaultHostname   string
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

// director modifies the request before sending it to the backend.
func (p *HTTPSProxy) director(r *http.Request) {
	if p.verbose {
		log.Printf("[request] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
	}

	// Rewrite the request to target the backend
	r.URL.Scheme = p.backend.Scheme
	r.URL.Host = p.backend.Host
	if p.backend.Path != "" {
		r.URL.Path = p.backend.Path + r.URL.Path
	}

	// Apply header transformation
	if err := p.headerTransformer(r, p.backend); err != nil {
		log.Printf("Header transformation error: %v", err)
	}

	// Clear request host to match the backend
	r.RequestURI = ""
	r.Host = p.backend.Host
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

// isACMEChallenge checks if the HTTP request is an ACME HTTP-01 challenge verification request.
func isACMEChallenge(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") || r.URL.Path == "/.well-known/acme-challenge"
}

// redirectTarget builds the target HTTPS URL for an incoming HTTP request.
func (p *HTTPSProxy) redirectTarget(r *http.Request) (string, error) {
	host := r.Host
	if host == "" {
		host = p.defaultHostname
	}
	if host == "" {
		return "", fmt.Errorf("missing Host header")
	}

	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
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
		log.Printf("[http] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
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
		log.Printf("[http] Redirecting %s to %s", r.RequestURI, targetURL)
	}

	http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
}

// ServeTLS starts the HTTPS server with Let's Encrypt certificates.
func (p *HTTPSProxy) ServeTLS(listener net.Listener, certManager *autocert.Manager) error {
	p.httpsServer = &http.Server{
		Addr:    listener.Addr().String(),
		Handler: http.HandlerFunc(p.serveProxy),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
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
		log.Printf("[https] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
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
	reverseProxy      *httputil.ReverseProxy
	httpServer        *http.Server
	headerTransformer HeaderTransformer
	verbose           bool
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

// director modifies the request before sending it to the backend.
func (p *HTTPProxy) director(r *http.Request) {
	if p.verbose {
		log.Printf("[request] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
	}

	// Rewrite the request to target the backend
	r.URL.Scheme = p.backend.Scheme
	r.URL.Host = p.backend.Host
	if p.backend.Path != "" {
		r.URL.Path = p.backend.Path + r.URL.Path
	}

	// Apply header transformation
	if err := p.headerTransformer(r, p.backend); err != nil {
		log.Printf("Header transformation error: %v", err)
	}

	// Clear request host to match the backend
	r.RequestURI = ""
	r.Host = p.backend.Host
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
		log.Printf("[http] %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
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
