package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	hostname  = flag.String("hostname", "", "Hostname for the HTTPS server (required)")
	backend   = flag.String("backend", "", "Backend HTTP address to proxy to (required)")
	port      = flag.Int("port", 443, "Port to listen on for HTTPS")
	cacheDir  = flag.String("cache-dir", "", "Directory to cache certificates (default: $HOME/.cache/https-proxy)")
	httpPort  = flag.Int("http-port", 80, "Port to listen on for HTTP (ACME challenges)")
	verbose   = flag.Bool("verbose", false, "Enable verbose request logging")
)

func main() {
	flag.Parse()

	// Validate required flags
	if *hostname == "" {
		log.Fatal("--hostname flag is required")
	}
	if *backend == "" {
		log.Fatal("--backend flag is required")
	}

	// Parse and validate backend URL
	backendURL, err := url.Parse(*backend)
	if err != nil {
		log.Fatalf("Invalid backend URL: %v", err)
	}
	if backendURL.Scheme != "http" && backendURL.Scheme != "https" {
		log.Fatal("Backend URL must have http or https scheme")
	}

	// Setup cache directory
	if *cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Could not determine home directory: %v", err)
		}
		*cacheDir = filepath.Join(homeDir, ".cache", "https-proxy")
	}

	if err := os.MkdirAll(*cacheDir, 0700); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	log.Printf("Cache directory: %s", *cacheDir)
	log.Printf("Backend: %s", backendURL.String())
	log.Printf("HTTPS listening on :%d (hostname: %s)", *port, *hostname)
	log.Printf("HTTP listening on :%d (for ACME challenges)", *httpPort)

	// Create certificate manager
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*hostname),
		Cache:      autocert.DirCache(*cacheDir),
	}

	// Create proxy
	proxy := NewHTTPSProxy(backendURL, certManager, *verbose)

	// Start HTTP server for ACME challenges
	go func() {
		addr := fmt.Sprintf(":%d", *httpPort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen on HTTP port: %v", err)
		}
		log.Printf("HTTP server started on port %d for ACME challenges", *httpPort)

		err = proxy.serveHTTP(listener)
		if err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on HTTPS port: %v", err)
	}
	defer listener.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v", sig)
		log.Printf("Shutting down gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := proxy.Shutdown(ctx); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}

		os.Exit(0)
	}()

	err = proxy.ServeTLS(listener, certManager)
	if err != nil {
		log.Fatalf("HTTPS server error: %v", err)
	}
}
