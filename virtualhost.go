package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// VirtualHost represents a single virtual host configuration with hostname and backend URL.
type VirtualHost struct {
	Hostname string `json:"hostname"`
	Backend  string `json:"backend"`
}

// VirtualHostConfig holds all virtual host configurations.
type VirtualHostConfig struct {
	VirtualHosts []VirtualHost `json:"virtual_hosts"`
}

// LoadVirtualHostConfig loads virtual host configuration from a JSON file.
// Format: { "virtual_hosts": [ { "hostname": "example.com", "backend": "http://localhost:8080" }, ... ] }
func LoadVirtualHostConfig(filePath string) (*VirtualHostConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read virtual hosts config file %s: %w", filePath, err)
	}

	var cfg VirtualHostConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse virtual hosts config JSON: %w", err)
	}

	if len(cfg.VirtualHosts) == 0 {
		return nil, fmt.Errorf("virtual hosts config contains no virtual hosts")
	}

	// Validate all virtual hosts
	for i, vh := range cfg.VirtualHosts {
		if vh.Hostname == "" {
			return nil, fmt.Errorf("virtual host at index %d has empty hostname", i)
		}
		if vh.Backend == "" {
			return nil, fmt.Errorf("virtual host %q has empty backend", vh.Hostname)
		}

		// Validate backend URL format
		backendURL, err := url.Parse(vh.Backend)
		if err != nil {
			return nil, fmt.Errorf("virtual host %q has invalid backend URL %q: %w", vh.Hostname, vh.Backend, err)
		}
		if backendURL.Scheme != "http" && backendURL.Scheme != "https" {
			return nil, fmt.Errorf("virtual host %q backend URL must have http or https scheme", vh.Hostname)
		}
	}

	return &cfg, nil
}

// GetAllHostnames returns a list of all hostnames in the configuration.
func (cfg *VirtualHostConfig) GetAllHostnames() []string {
	hostnames := make([]string, len(cfg.VirtualHosts))
	for i, vh := range cfg.VirtualHosts {
		hostnames[i] = vh.Hostname
	}
	return hostnames
}

// GetBackendURL returns the backend URL for a given hostname.
// Returns an error if the hostname is not found.
func (cfg *VirtualHostConfig) GetBackendURL(hostname string) (*url.URL, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	// Try exact match first
	for _, vh := range cfg.VirtualHosts {
		if strings.EqualFold(vh.Hostname, hostname) {
			backendURL, err := url.Parse(vh.Backend)
			if err != nil {
				return nil, fmt.Errorf("invalid backend URL for hostname %q: %w", hostname, err)
			}
			return backendURL, nil
		}
	}

	return nil, fmt.Errorf("no backend configured for hostname %q", hostname)
}

// ToBackendURLMap converts the virtual host config to a simple map for quick lookup.
func (cfg *VirtualHostConfig) ToBackendURLMap() (map[string]*url.URL, error) {
	m := make(map[string]*url.URL)
	for _, vh := range cfg.VirtualHosts {
		backendURL, err := url.Parse(vh.Backend)
		if err != nil {
			return nil, fmt.Errorf("invalid backend URL for hostname %q: %w", vh.Hostname, err)
		}
		m[strings.ToLower(vh.Hostname)] = backendURL
	}
	return m, nil
}
