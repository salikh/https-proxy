package main

import (
	"io"
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
