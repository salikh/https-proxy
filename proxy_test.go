package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// TestHeaderTransformerRemovesHopByHopHeaders verifies that hop-by-hop headers are removed.
func TestHeaderTransformerRemovesHopByHopHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/path", nil)
	r.Header.Set("Connection", "close")
	r.Header.Set("Transfer-Encoding", "chunked")
	r.Header.Set("Keep-Alive", "timeout=5")

	backendURL, _ := url.Parse("http://localhost:8080")
	err := defaultHeaderTransformer(r, backendURL)

	if err != nil {
		t.Fatalf("Header transformer failed: %v", err)
	}

	if r.Header.Get("Connection") != "" {
		t.Error("Connection header should be removed")
	}
	if r.Header.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding header should be removed")
	}
	if r.Header.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be removed")
	}
}

// TestHeaderTransformerAddsForwardedHeaders verifies that X-Forwarded headers are added.
func TestHeaderTransformerAddsForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/path", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("Host", "example.com")

	backendURL, _ := url.Parse("http://localhost:8080")
	err := defaultHeaderTransformer(r, backendURL)

	if err != nil {
		t.Fatalf("Header transformer failed: %v", err)
	}

	if r.Header.Get("X-Forwarded-Proto") != "https" {
		t.Error("X-Forwarded-Proto should be set to https")
	}
	if r.Header.Get("X-Forwarded-Host") != "example.com" {
		t.Error("X-Forwarded-Host should be set to the original host")
	}
	if r.Header.Get("X-Forwarded-For") != "192.168.1.1:5000" {
		t.Error("X-Forwarded-For should be set to the remote address")
	}
}

// TestHeaderTransformerDoesNotOverwriteExistingForwardedHeaders verifies that existing X-Forwarded headers are preserved.
func TestHeaderTransformerDoesNotOverwriteExistingForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/path", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Forwarded-Host", "original.example.com")

	backendURL, _ := url.Parse("http://localhost:8080")
	err := defaultHeaderTransformer(r, backendURL)

	if err != nil {
		t.Fatalf("Header transformer failed: %v", err)
	}

	if r.Header.Get("X-Forwarded-For") != "10.0.0.1" {
		t.Error("X-Forwarded-For should not be overwritten if already set")
	}
	if r.Header.Get("X-Forwarded-Host") != "original.example.com" {
		t.Error("X-Forwarded-Host should not be overwritten if already set")
	}
}

// TestProxyDirector verifies that the director correctly rewrites request URLs.
func TestProxyDirector(t *testing.T) {
	backendURL, _ := url.Parse("http://backend.example.com:8080")
	tmpDir := t.TempDir()
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(tmpDir),
	}
	proxy := NewHTTPSProxy(backendURL, certManager, false)

	r := httptest.NewRequest("GET", "/api/users", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("Host", "example.com")

	proxy.director(r)

	if r.URL.Scheme != "http" {
		t.Errorf("Expected scheme http, got %s", r.URL.Scheme)
	}
	if r.URL.Host != "backend.example.com:8080" {
		t.Errorf("Expected host backend.example.com:8080, got %s", r.URL.Host)
	}
	if r.URL.Path != "/api/users" {
		t.Errorf("Expected path /api/users, got %s", r.URL.Path)
	}
	if r.Host != "backend.example.com:8080" {
		t.Errorf("Expected Host header backend.example.com:8080, got %s", r.Host)
	}
}

// TestProxyDirectorWithBackendPath verifies that backend path is prepended correctly.
func TestProxyDirectorWithBackendPath(t *testing.T) {
	backendURL, _ := url.Parse("http://backend.example.com:8080/v1")
	tmpDir := t.TempDir()
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(tmpDir),
	}
	proxy := NewHTTPSProxy(backendURL, certManager, false)

	r := httptest.NewRequest("GET", "/users", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("Host", "example.com")

	proxy.director(r)

	if r.URL.Path != "/v1/users" {
		t.Errorf("Expected path /v1/users, got %s", r.URL.Path)
	}
}

// TestProxyForwardsRequests verifies that requests are forwarded correctly to the backend.
func TestProxyForwardsRequests(t *testing.T) {
	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/test" {
			t.Errorf("Expected path /api/test, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Error("X-Forwarded-Proto header not set correctly")
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "backend response")
	}))
	defer backend.Close()

	// Parse backend URL
	backendURL, _ := url.Parse(backend.URL)

	tmpDir := t.TempDir()
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(tmpDir),
	}
	proxy := NewHTTPSProxy(backendURL, certManager, false)

	// Create a test request
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("Host", "example.com")

	// Create a response recorder
	w := httptest.NewRecorder()

	// Serve the request through the proxy
	proxy.reverseProxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "backend response" {
		t.Errorf("Expected 'backend response', got %q", body)
	}
}

// TestProxyHandlesBackendError verifies that backend errors are handled correctly.
func TestProxyHandlesBackendError(t *testing.T) {
	// Create a backend URL that doesn't exist
	backendURL, _ := url.Parse("http://nonexistent.local:9999")

	tmpDir := t.TempDir()
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(tmpDir),
	}
	proxy := NewHTTPSProxy(backendURL, certManager, false)

	// Create a test request
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "192.168.1.1:5000"
	r.Header.Set("Host", "example.com")

	// Create a response recorder
	w := httptest.NewRecorder()

	// Serve the request through the proxy (should handle the error)
	proxy.reverseProxy.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}
}

// TestProxyPreservesHTTPMethods verifies that all HTTP methods are forwarded correctly.
func TestProxyPreservesHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Create a mock backend server
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method {
					t.Errorf("Expected method %s, got %s", method, r.Method)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			// Parse backend URL
			backendURL, _ := url.Parse(backend.URL)

			tmpDir := t.TempDir()
			certManager := &autocert.Manager{
				Prompt:      autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist("example.com"),
				Cache:      autocert.DirCache(tmpDir),
			}
			proxy := NewHTTPSProxy(backendURL, certManager, false)

			// Create a test request
			var r *http.Request
			if method == "POST" || method == "PUT" || method == "PATCH" {
				r = httptest.NewRequest(method, "/test", strings.NewReader("test body"))
			} else {
				r = httptest.NewRequest(method, "/test", nil)
			}
			r.RemoteAddr = "192.168.1.1:5000"
			r.Header.Set("Host", "example.com")

			// Create a response recorder
			w := httptest.NewRecorder()

			// Serve the request through the proxy
			proxy.reverseProxy.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}
		})
	}
}

// TestHTTPRedirectToHTTPS verifies that HTTP requests are redirected to HTTPS.
func TestHTTPRedirectToHTTPS(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)

	req := httptest.NewRequest("GET", "/test/path?foo=bar&baz=qux", nil)
	req.Host = "example.com"

	w := httptest.NewRecorder()
	proxy.handleHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected status %d, got %d", http.StatusMovedPermanently, w.Code)
	}

	expectedLocation := "https://example.com/test/path?foo=bar&baz=qux"
	if loc := w.Header().Get("Location"); loc != expectedLocation {
		t.Errorf("Expected Location header %q, got %q", expectedLocation, loc)
	}
}

// TestHTTPRedirectWithCustomPort verifies that redirects include the custom HTTPS port.
func TestHTTPRedirectWithCustomPort(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)
	proxy.SetHTTPSPort(8443)

	req := httptest.NewRequest("GET", "/hello", nil)
	req.Host = "example.com:8080"

	w := httptest.NewRecorder()
	proxy.handleHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected status %d, got %d", http.StatusMovedPermanently, w.Code)
	}

	expectedLocation := "https://example.com:8443/hello"
	if loc := w.Header().Get("Location"); loc != expectedLocation {
		t.Errorf("Expected Location header %q, got %q", expectedLocation, loc)
	}
}

// TestHTTPRedirectIPv6Host verifies that IPv6 hosts are handled properly.
func TestHTTPRedirectIPv6Host(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)

	// Port 443
	req := httptest.NewRequest("GET", "/path", nil)
	req.Host = "[::1]:80"
	w := httptest.NewRecorder()
	proxy.handleHTTP(w, req)

	if loc := w.Header().Get("Location"); loc != "https://[::1]/path" {
		t.Errorf("Expected https://[::1]/path, got %q", loc)
	}

	// Custom port
	proxy.SetHTTPSPort(8443)
	req2 := httptest.NewRequest("GET", "/path", nil)
	req2.Host = "[::1]:8080"
	w2 := httptest.NewRecorder()
	proxy.handleHTTP(w2, req2)

	if loc := w2.Header().Get("Location"); loc != "https://[::1]:8443/path" {
		t.Errorf("Expected https://[::1]:8443/path, got %q", loc)
	}
}

// TestHTTPRedirectDefaultHostnameFallback verifies fallback to defaultHostname when Host is empty.
func TestHTTPRedirectDefaultHostnameFallback(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)
	proxy.SetDefaultHostname("fallback.example.com")

	req := httptest.NewRequest("GET", "/about", nil)
	req.Host = ""

	w := httptest.NewRecorder()
	proxy.handleHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected status %d, got %d", http.StatusMovedPermanently, w.Code)
	}

	if loc := w.Header().Get("Location"); loc != "https://fallback.example.com/about" {
		t.Errorf("Expected https://fallback.example.com/about, got %q", loc)
	}
}

// TestACMEChallengeNotRedirected verifies that ACME challenge requests are never redirected to HTTPS.
func TestACMEChallengeNotRedirected(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)

	acmePaths := []string{
		"/.well-known/acme-challenge/token123",
		"/.well-known/acme-challenge/token-xyz-456",
		"/.well-known/acme-challenge",
	}

	for _, p := range acmePaths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest("GET", p, nil)
			req.Host = "example.com"

			w := httptest.NewRecorder()
			proxy.handleHTTP(w, req)

			if w.Code == http.StatusMovedPermanently || w.Code == http.StatusFound || w.Code == http.StatusPermanentRedirect {
				t.Fatalf("ACME challenge %s was redirected (status %d)", p, w.Code)
			}
			if w.Code != http.StatusNotFound {
				t.Errorf("Expected 404 Not Found for unhandled ACME challenge, got %d", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("ACME challenge response contained Location header: %q", loc)
			}
		})
	}
}

// TestServeHTTPWithAutocertManager verifies that serveHTTP integrates with autocert.Manager.
func TestServeHTTPWithAutocertManager(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	tmpDir := t.TempDir()
	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(tmpDir),
	}
	proxy := NewHTTPSProxy(backendURL, certManager, false)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = proxy.serveHTTP(listener)
	}()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Regular HTTP request should be redirected to HTTPS
	resp, err := client.Get("http://" + listener.Addr().String() + "/some/path?query=1")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected 301, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://") || !strings.Contains(loc, "/some/path?query=1") {
		t.Errorf("Unexpected Location: %s", loc)
	}

	// 2. ACME challenge request to an unknown token should NOT be redirected
	req2, err := http.NewRequest("GET", "http://"+listener.Addr().String()+"/.well-known/acme-challenge/dummy-token", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req2.Host = "example.com"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Failed to send ACME request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusMovedPermanently || resp2.StatusCode == http.StatusFound || resp2.StatusCode == http.StatusPermanentRedirect {
		t.Errorf("ACME challenge was redirected with status %d to %s", resp2.StatusCode, resp2.Header.Get("Location"))
	}
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 for unknown ACME challenge, got %d", resp2.StatusCode)
	}
}

// TestHTTPRedirectIPToDefaultHostname verifies that requests with an IP Host header are redirected
// to the configured default hostname rather than redirecting to an IP address.
func TestHTTPRedirectIPToDefaultHostname(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backendURL, nil, false)
	proxy.SetDefaultHostname("part.salikh.info")

	testCases := []struct {
		name     string
		host     string
		path     string
		expected string
	}{
		{
			name:     "LAN IPv4 address",
			host:     "192.168.1.1",
			path:     "/",
			expected: "https://part.salikh.info/",
		},
		{
			name:     "LAN IPv4 address with port",
			host:     "192.168.1.1:80",
			path:     "/api/v1",
			expected: "https://part.salikh.info/api/v1",
		},
		{
			name:     "Localhost",
			host:     "localhost",
			path:     "/test",
			expected: "https://part.salikh.info/test",
		},
		{
			name:     "Canonical hostname",
			host:     "part.salikh.info",
			path:     "/test",
			expected: "https://part.salikh.info/test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Host = tc.host

			w := httptest.NewRecorder()
			proxy.handleHTTP(w, req)

			if w.Code != http.StatusMovedPermanently {
				t.Fatalf("Expected status %d, got %d", http.StatusMovedPermanently, w.Code)
			}

			if loc := w.Header().Get("Location"); loc != tc.expected {
				t.Errorf("Expected Location %q, got %q", tc.expected, loc)
			}
		})
	}
}

// TestHTTPRedirectWithVirtualHosts tests HTTP redirect behavior with virtual hosts configured.
func TestHTTPRedirectWithVirtualHosts(t *testing.T) {
	backend, _ := url.Parse("http://localhost:8080")
	proxy := NewHTTPSProxy(backend, nil, false)
	proxy.SetHTTPSPort(443)
	proxy.SetDefaultHostname("default.example.com")

	// Set up virtual hosts
	virtualHosts := map[string]*url.URL{
		"api.example.com": backend,
		"web.example.com": backend,
	}
	proxy.SetVirtualHosts(virtualHosts)

	testCases := []struct {
		hostHeader       string
		expectedLocation string
		description      string
	}{
		{
			"api.example.com",
			"https://api.example.com/test",
			"Request to virtual host should redirect to same hostname",
		},
		{
			"web.example.com",
			"https://web.example.com/test",
			"Request to different virtual host should redirect to same hostname",
		},
		{
			"unknown.example.com",
			"https://default.example.com/test",
			"Request to unknown hostname should redirect to default hostname",
		},
		{
			"api.example.com:8080",
			"https://api.example.com/test",
			"Request with port should strip port and redirect to hostname only",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Host = tc.hostHeader
			w := httptest.NewRecorder()

			proxy.handleHTTP(w, req)

			if w.Code != http.StatusMovedPermanently {
				t.Errorf("Expected 301 redirect, got %d", w.Code)
			}

			location := w.Header().Get("Location")
			if location != tc.expectedLocation {
				t.Errorf("Expected location %q, got %q", tc.expectedLocation, location)
			}
		})
	}
}


