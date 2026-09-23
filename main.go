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
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	hostname            = flag.String("hostname", "", "Hostname for the server (required for HTTPS)")
	backend             = flag.String("backend", "", "Backend HTTP address to proxy to (required)")
	port                = flag.Int("port", 443, "Port to listen on")
	httpPort            = flag.Int("http-port", 80, "Port to listen on for HTTP (ACME challenges and HTTPS redirects, or plain HTTP mode)")
	cacheDir            = flag.String("cache-dir", "", "Directory to cache Let's Encrypt certificates (default: $HOME/.cache/https-proxy)")
	verbose             = flag.Bool("verbose", false, "Enable verbose request logging")
	noTLS               = flag.Bool("no-tls", false, "Run as HTTP proxy instead of HTTPS")
	selfSigned          = flag.Bool("self-signed", false, "Use self-signed certificates instead of Let's Encrypt")
	selfSignedDir       = flag.String("self-signed-dir", "", "Directory for self-signed certs (default: $HOME/.cache/https-proxy-selfsigned)")
	certFile            = flag.String("cert", "", "Path to certificate file (for manual cert management)")
	keyFile             = flag.String("key", "", "Path to key file (for manual cert management)")
	oauth               = flag.Bool("oauth", false, "Enforce Google OAuth authentication on all requests (except ACME challenges)")
	oauthSecret         = flag.String("oauth-secret", "secret.json", "Path to OAuth client secret JSON file (plaintext or encrypted .enc), or raw JSON")
	oauthPassphrase     = flag.String("oauth-passphrase", "", "Passphrase to decrypt encrypted OAuth secret file (can also use OAUTH_PASSPHRASE env var)")
	oauthAllowedUsers   = flag.String("oauth-allowed-users", "", "Comma-separated list of allowed user emails (default: allow any authenticated Google user)")
	oauthAllowedFile    = flag.String("oauth-allowed-file", "allowed.txt", "Path to file containing allowed user emails (one per line, default: allowed.txt if exists)")
	oauthAllowedDomains = flag.String("oauth-allowed-domains", "", "Comma-separated list of allowed email domains (e.g. example.com)")
	encryptSecret       = flag.String("encrypt-secret", "", "Path to plaintext OAuth secret JSON file to encrypt and exit")
	encryptSecretOut    = flag.String("encrypt-secret-out", "", "Output path for encrypted secret file (default: input + .enc)")
)

func main() {
	flag.Parse()

	// If -encrypt-secret is specified, perform encryption and exit
	if *encryptSecret != "" {
		handleEncryptSecretCLI(*encryptSecret, *encryptSecretOut, *oauthPassphrase)
		return
	}

	// Validate required flags
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

	log.Printf("Backend: %s", backendURL.String())

	// Handle HTTP-only mode
	if *noTLS {
		runHTTPProxy(backendURL)
		return
	}

	// HTTPS mode - require hostname
	if *hostname == "" {
		log.Fatal("--hostname flag is required for HTTPS mode (use --no-tls for HTTP-only mode)")
	}

	log.Printf("HTTPS listening on :%d (hostname: %s)", *port, *hostname)
	log.Printf("HTTP listening on :%d (for ACME challenges and HTTPS redirects)", *httpPort)

	runHTTPSProxy(backendURL)

}

func runHTTPSProxy(backendURL *url.URL) {
	// Setup certificate cache directory
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

	log.Printf("Certificate cache: %s", *cacheDir)

	var certManager interface{} // Can be *autocert.Manager or nil

	// Determine which certificate mode to use
	if *selfSigned {
		// Self-signed mode
		if *selfSignedDir == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Could not determine home directory: %v", err)
			}
			*selfSignedDir = filepath.Join(homeDir, ".cache", "https-proxy-selfsigned")
		}

		if err := os.MkdirAll(*selfSignedDir, 0700); err != nil {
			log.Fatalf("Failed to create self-signed cert directory: %v", err)
		}

		log.Printf("Self-signed cert directory: %s", *selfSignedDir)

		// Set cert and key paths for self-signed mode
		*certFile = filepath.Join(*selfSignedDir, "cert.pem")
		*keyFile = filepath.Join(*selfSignedDir, "key.pem")

		// Check if certs exist, if not error out
		if _, err := os.Stat(*certFile); os.IsNotExist(err) {
			log.Fatalf("Self-signed certificate not found at %s. Run: generate-self-signed-cert.sh --hostname %s --output-dir %s", *certFile, *hostname, *selfSignedDir)
		}

		log.Printf("Using self-signed certificate: %s", *certFile)
	} else if *certFile != "" && *keyFile != "" {
		// Manual cert mode
		if _, err := os.Stat(*certFile); os.IsNotExist(err) {
			log.Fatalf("Certificate file not found: %s", *certFile)
		}
		if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
			log.Fatalf("Key file not found: %s", *keyFile)
		}
		log.Printf("Using certificate: %s", *certFile)
	} else {
		// Let's Encrypt mode (default)
		certManager = &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*hostname),
			Cache:      autocert.DirCache(*cacheDir),
		}
		log.Printf("Using Let's Encrypt certificates")
	}

	// Create proxy
	proxy := NewHTTPSProxy(backendURL, certManager, *verbose)
	proxy.SetHTTPSPort(*port)
	proxy.SetDefaultHostname(*hostname)

	if oauthMgr := setupOAuth(true); oauthMgr != nil {
		proxy.SetOAuthManager(oauthMgr)
	}

	// Start HTTP server for ACME challenges and HTTPS redirects
	go func() {
		addr := fmt.Sprintf(":%d", *httpPort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen on HTTP port: %v", err)
		}
		log.Printf("HTTP server started on port %d", *httpPort)

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

	if *selfSigned || (*certFile != "" && *keyFile != "") {
		// Use manual cert files
		err = proxy.ServeTLSWithFiles(listener, *certFile, *keyFile)
	} else {
		// Use Let's Encrypt
		err = proxy.ServeTLS(listener, certManager.(*autocert.Manager))
	}

	if err != nil {
		log.Fatalf("HTTPS server error: %v", err)
	}
}

func runHTTPProxy(backendURL *url.URL) {
	// Create proxy
	proxy := NewHTTPProxy(backendURL, *verbose)

	if oauthMgr := setupOAuth(false); oauthMgr != nil {
		proxy.SetOAuthManager(oauthMgr)
	}

	log.Printf("HTTP listening on :%d", *httpPort)
	log.Printf("Starting HTTP proxy (no TLS)")

	addr := fmt.Sprintf(":%d", *httpPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on port: %v", err)
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

	err = proxy.ServeHTTP(listener)
	if err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}

func setupOAuth(secureCookie bool) *OAuthManager {
	if !*oauth {
		return nil
	}

	secretData, err := LoadOAuthSecret(*oauthSecret, *oauthPassphrase)
	if err != nil {
		log.Fatalf("Failed to load OAuth secret: %v", err)
	}

	var allowedUsers []string
	if *oauthAllowedFile != "" {
		if _, err := os.Stat(*oauthAllowedFile); err == nil {
			usersFromFile, err := LoadAllowedUsersFromFile(*oauthAllowedFile)
			if err != nil {
				log.Fatalf("Failed to load allowed users from %s: %v", *oauthAllowedFile, err)
			}
			allowedUsers = append(allowedUsers, usersFromFile...)
			log.Printf("Loaded %d allowed users from %s", len(usersFromFile), *oauthAllowedFile)
		} else if *oauthAllowedFile != "allowed.txt" {
			log.Fatalf("Specified allowed users file %s not found: %v", *oauthAllowedFile, err)
		}
	}

	if *oauthAllowedUsers != "" {
		for _, u := range strings.Split(*oauthAllowedUsers, ",") {
			if trimmed := strings.TrimSpace(u); trimmed != "" {
				allowedUsers = append(allowedUsers, trimmed)
			}
		}
	}

	var allowedDomains []string
	if *oauthAllowedDomains != "" {
		for _, d := range strings.Split(*oauthAllowedDomains, ",") {
			if trimmed := strings.TrimSpace(d); trimmed != "" {
				allowedDomains = append(allowedDomains, trimmed)
			}
		}
	}

	mgr, err := NewOAuthManager(secretData, OAuthOptions{
		AllowedUsers:   allowedUsers,
		AllowedDomains: allowedDomains,
		SecureCookie:   secureCookie,
		Verbose:        *verbose,
	})
	if err != nil {
		log.Fatalf("Failed to initialize OAuth manager: %v", err)
	}

	log.Printf("OAuth authentication ENFORCED (callback: %s)", mgr.callbackPath)
	if len(allowedUsers) > 0 {
		log.Printf("OAuth allowed users: %s", strings.Join(allowedUsers, ", "))
	}
	if len(allowedDomains) > 0 {
		log.Printf("OAuth allowed domains: %s", strings.Join(allowedDomains, ", "))
	}

	return mgr
}
