package main

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleVirtualHostsJSON = `{
  "virtual_hosts": [
    {
      "hostname": "api.example.com",
      "backend": "http://localhost:8080"
    },
    {
      "hostname": "web.example.com",
      "backend": "http://localhost:3000"
    },
    {
      "hostname": "app.example.com",
      "backend": "https://internal-app:8443"
    }
  ]
}`

// TestLoadVirtualHostConfig verifies loading virtual host configuration from JSON file.
func TestLoadVirtualHostConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := LoadVirtualHostConfig(configFile)
	if err != nil {
		t.Fatalf("LoadVirtualHostConfig failed: %v", err)
	}

	if len(cfg.VirtualHosts) != 3 {
		t.Errorf("Expected 3 virtual hosts, got %d", len(cfg.VirtualHosts))
	}

	expectedHosts := []string{"api.example.com", "web.example.com", "app.example.com"}
	for i, expected := range expectedHosts {
		if cfg.VirtualHosts[i].Hostname != expected {
			t.Errorf("Virtual host %d: expected hostname %q, got %q", i, expected, cfg.VirtualHosts[i].Hostname)
		}
	}
}

// TestLoadVirtualHostConfigInvalidFile verifies error handling for missing file.
func TestLoadVirtualHostConfigInvalidFile(t *testing.T) {
	_, err := LoadVirtualHostConfig("/nonexistent/path/vhosts.json")
	if err == nil {
		t.Error("Expected error for nonexistent config file, but got nil")
	}
}

// TestLoadVirtualHostConfigInvalidJSON verifies error handling for malformed JSON.
func TestLoadVirtualHostConfigInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(configFile, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for invalid JSON, but got nil")
	}
}

// TestLoadVirtualHostConfigEmptyHosts verifies error handling for empty virtual hosts.
func TestLoadVirtualHostConfigEmptyHosts(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty.json")
	emptyJSON := `{ "virtual_hosts": [] }`

	if err := os.WriteFile(configFile, []byte(emptyJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for empty virtual hosts, but got nil")
	}
}

// TestLoadVirtualHostConfigMissingHostname verifies error handling for missing hostname.
func TestLoadVirtualHostConfigMissingHostname(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "missing-hostname.json")
	jsonData := `{
  "virtual_hosts": [
    { "backend": "http://localhost:8080" }
  ]
}`

	if err := os.WriteFile(configFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for missing hostname, but got nil")
	}
}

// TestLoadVirtualHostConfigMissingBackend verifies error handling for missing backend.
func TestLoadVirtualHostConfigMissingBackend(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "missing-backend.json")
	jsonData := `{
  "virtual_hosts": [
    { "hostname": "example.com" }
  ]
}`

	if err := os.WriteFile(configFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for missing backend, but got nil")
	}
}

// TestLoadVirtualHostConfigInvalidBackendURL verifies error handling for invalid backend URLs.
func TestLoadVirtualHostConfigInvalidBackendURL(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid-backend.json")
	jsonData := `{
  "virtual_hosts": [
    { "hostname": "example.com", "backend": "not-a-valid-url" }
  ]
}`

	if err := os.WriteFile(configFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for invalid backend URL, but got nil")
	}
}

// TestLoadVirtualHostConfigInvalidScheme verifies error handling for invalid URL schemes.
func TestLoadVirtualHostConfigInvalidScheme(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid-scheme.json")
	jsonData := `{
  "virtual_hosts": [
    { "hostname": "example.com", "backend": "ftp://localhost:8080" }
  ]
}`

	if err := os.WriteFile(configFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	_, err := LoadVirtualHostConfig(configFile)
	if err == nil {
		t.Error("Expected error for invalid URL scheme, but got nil")
	}
}

// TestGetAllHostnames verifies retrieving all hostnames from config.
func TestGetAllHostnames(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, _ := LoadVirtualHostConfig(configFile)
	hostnames := cfg.GetAllHostnames()

	if len(hostnames) != 3 {
		t.Errorf("Expected 3 hostnames, got %d", len(hostnames))
	}

	expected := []string{"api.example.com", "web.example.com", "app.example.com"}
	for i, h := range hostnames {
		if h != expected[i] {
			t.Errorf("Hostname %d: expected %q, got %q", i, expected[i], h)
		}
	}
}

// TestGetBackendURL verifies retrieving backend URL for a specific hostname.
func TestGetBackendURL(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, _ := LoadVirtualHostConfig(configFile)

	testCases := []struct {
		hostname    string
		expectedURL string
	}{
		{"api.example.com", "http://localhost:8080"},
		{"web.example.com", "http://localhost:3000"},
		{"app.example.com", "https://internal-app:8443"},
		{"API.EXAMPLE.COM", "http://localhost:8080"}, // case insensitive
	}

	for _, tc := range testCases {
		backendURL, err := cfg.GetBackendURL(tc.hostname)
		if err != nil {
			t.Errorf("GetBackendURL(%q) failed: %v", tc.hostname, err)
			continue
		}

		if backendURL.String() != tc.expectedURL {
			t.Errorf("GetBackendURL(%q): expected %q, got %q", tc.hostname, tc.expectedURL, backendURL.String())
		}
	}
}

// TestGetBackendURLNotFound verifies error handling for unknown hostname.
func TestGetBackendURLNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, _ := LoadVirtualHostConfig(configFile)

	_, err := cfg.GetBackendURL("unknown.example.com")
	if err == nil {
		t.Error("Expected error for unknown hostname, but got nil")
	}
}

// TestToBackendURLMap verifies converting config to backend URL map.
func TestToBackendURLMap(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, _ := LoadVirtualHostConfig(configFile)
	backendMap, err := cfg.ToBackendURLMap()
	if err != nil {
		t.Fatalf("ToBackendURLMap failed: %v", err)
	}

	if len(backendMap) != 3 {
		t.Errorf("Expected 3 entries in map, got %d", len(backendMap))
	}

	// Verify lookup by lowercase key
	if _, ok := backendMap["api.example.com"]; !ok {
		t.Error("Expected to find api.example.com in backend map")
	}

	if _, ok := backendMap["web.example.com"]; !ok {
		t.Error("Expected to find web.example.com in backend map")
	}

	if _, ok := backendMap["app.example.com"]; !ok {
		t.Error("Expected to find app.example.com in backend map")
	}
}

// TestVirtualHostBackendMap tests backend map creation from config.
func TestVirtualHostBackendMap(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "vhosts.json")

	if err := os.WriteFile(configFile, []byte(sampleVirtualHostsJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, _ := LoadVirtualHostConfig(configFile)
	backendMap, err := cfg.ToBackendURLMap()
	if err != nil {
		t.Fatalf("ToBackendURLMap failed: %v", err)
	}

	testCases := []struct {
		hostHeader    string
		expectedHost  string
		expectedPort  string
	}{
		{"api.example.com", "localhost", "8080"},
		{"web.example.com", "localhost", "3000"},
		{"app.example.com", "internal-app", "8443"},
	}

	for _, tc := range testCases {
		backend, ok := backendMap[tc.hostHeader]
		if !ok {
			t.Errorf("Expected to find %q in backend map", tc.hostHeader)
			continue
		}

		if backend.Hostname() != tc.expectedHost {
			t.Errorf("For host %q: expected backend host %q, got %q", tc.hostHeader, tc.expectedHost, backend.Hostname())
		}

		if backend.Port() != tc.expectedPort {
			t.Errorf("For host %q: expected backend port %q, got %q", tc.hostHeader, tc.expectedPort, backend.Port())
		}
	}
}
