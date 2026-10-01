package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const sampleGoogleSecretJSON = `{
  "web": {
    "client_id": "test-client-id-123.apps.googleusercontent.com",
    "project_id": "test-project",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "GOCSPX-test-client-secret-abc",
    "redirect_uris": [
      "https://part.salikh.info/callback"
    ],
    "javascript_origins": [
      "https://part.salikh.info"
    ]
  }
}`

// TestEncryptAndDecryptSecret tests AES-256-GCM encryption and decryption.
func TestEncryptAndDecryptSecret(t *testing.T) {
	passphrase := "MySecurePassphrase123!"
	plaintext := []byte(sampleGoogleSecretJSON)

	encrypted, err := EncryptSecret(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	if bytesAreIdentical(plaintext, encrypted) {
		t.Fatal("Encrypted data is identical to plaintext")
	}

	if !strings.HasPrefix(string(encrypted), EncryptedHeaderMagic) {
		t.Fatalf("Encrypted data missing magic header %q", EncryptedHeaderMagic)
	}

	// Successful decryption with correct passphrase
	decrypted, err := DecryptSecret(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match plaintext.\nGot: %s\nWant: %s", string(decrypted), string(plaintext))
	}

	// Failed decryption with wrong passphrase
	_, err = DecryptSecret(encrypted, "WrongPassphrase")
	if err == nil {
		t.Error("Expected error decrypting with wrong passphrase, but got nil")
	}

	// Failed decryption with tampered ciphertext
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF
	_, err = DecryptSecret(tampered, passphrase)
	if err == nil {
		t.Error("Expected error decrypting tampered data, but got nil")
	}

	// Empty passphrase error
	_, err = EncryptSecret(plaintext, "")
	if err == nil {
		t.Error("Expected error with empty passphrase, but got nil")
	}
}

func bytesAreIdentical(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestLoadOAuthSecretPlaintextAndPermissionSecuring verifies that loading a plaintext
// secret checks permissions and tightens insecure permissions to 0600.
func TestLoadOAuthSecretPlaintextAndPermissionSecuring(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.json")

	// Write secret file with insecure permissions 0644
	err := os.WriteFile(secretFile, []byte(sampleGoogleSecretJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create test secret file: %v", err)
	}

	// Load the secret
	loaded, err := LoadOAuthSecret(secretFile, "")
	if err != nil {
		t.Fatalf("LoadOAuthSecret failed: %v", err)
	}

	if string(loaded) != sampleGoogleSecretJSON {
		t.Errorf("Loaded secret does not match expected JSON")
	}

	// Verify permissions were tightened to 0600
	info, err := os.Stat(secretFile)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected file permissions 0600, got %04o", info.Mode().Perm())
	}
}

// TestLoadOAuthSecretEncrypted verifies loading and decrypting an encrypted secret file.
func TestLoadOAuthSecretEncrypted(t *testing.T) {
	tmpDir := t.TempDir()
	encFile := filepath.Join(tmpDir, "secret.json.enc")
	passphrase := "TopSecretPassword!"

	encrypted, err := EncryptSecret([]byte(sampleGoogleSecretJSON), passphrase)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	if err := os.WriteFile(encFile, encrypted, 0600); err != nil {
		t.Fatalf("Failed to write encrypted secret file: %v", err)
	}

	// Test loading with passphrase
	loaded, err := LoadOAuthSecret(encFile, passphrase)
	if err != nil {
		t.Fatalf("LoadOAuthSecret failed on encrypted file: %v", err)
	}

	if string(loaded) != sampleGoogleSecretJSON {
		t.Errorf("Loaded decrypted secret does not match expected JSON")
	}

	// Test loading with OAUTH_PASSPHRASE env var
	t.Setenv("OAUTH_PASSPHRASE", passphrase)
	loadedEnv, err := LoadOAuthSecret(encFile, "")
	if err != nil {
		t.Fatalf("LoadOAuthSecret failed using OAUTH_PASSPHRASE env var: %v", err)
	}
	if string(loadedEnv) != sampleGoogleSecretJSON {
		t.Errorf("Loaded secret from env passphrase does not match expected JSON")
	}
}

// TestLoadOAuthSecretFromEnvVar verifies zero-disk secret loading via OAUTH_SECRET_JSON.
func TestLoadOAuthSecretFromEnvVar(t *testing.T) {
	t.Setenv("OAUTH_SECRET_JSON", sampleGoogleSecretJSON)

	loaded, err := LoadOAuthSecret("nonexistent.json", "")
	if err != nil {
		t.Fatalf("LoadOAuthSecret failed when OAUTH_SECRET_JSON was set: %v", err)
	}

	if string(loaded) != sampleGoogleSecretJSON {
		t.Errorf("Loaded secret does not match OAUTH_SECRET_JSON environment variable")
	}
}

// TestOAuthSessionCookieLifecycle verifies session cookie creation, validation, tampering, and expiration.
func TestOAuthSessionCookieLifecycle(t *testing.T) {
	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		SessionDuration: 1 * time.Hour,
		SecureCookie:    false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	email := "salikh@google.com"
	cookie := mgr.CreateSessionCookie(email)

	if cookie.Name != DefaultSessionCookieName {
		t.Errorf("Expected cookie name %s, got %s", DefaultSessionCookieName, cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("Expected HttpOnly cookie")
	}

	// Valid session request
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookie)

	authedUser, err := mgr.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("AuthenticateRequest failed on valid cookie: %v", err)
	}
	if authedUser != email {
		t.Errorf("Expected authenticated user %s, got %s", email, authedUser)
	}

	// Tampered cookie value
	tamperedCookie := &http.Cookie{
		Name:  DefaultSessionCookieName,
		Value: cookie.Value + "tampered",
	}
	reqTampered := httptest.NewRequest("GET", "/dashboard", nil)
	reqTampered.AddCookie(tamperedCookie)

	_, err = mgr.AuthenticateRequest(reqTampered)
	if err == nil {
		t.Error("Expected AuthenticateRequest to reject tampered cookie, but it succeeded")
	}

	// Expired session cookie
	mgrExpired, _ := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		SessionDuration: -1 * time.Hour, // expired
	})
	expiredCookie := mgrExpired.CreateSessionCookie(email)
	reqExpired := httptest.NewRequest("GET", "/dashboard", nil)
	reqExpired.AddCookie(expiredCookie)

	_, err = mgrExpired.AuthenticateRequest(reqExpired)
	if err == nil {
		t.Error("Expected AuthenticateRequest to reject expired cookie, but it succeeded")
	}
}

// TestOAuthStateCookieCSRFDefense tests state cookie creation, CSRF verification, and open redirect protection.
func TestOAuthStateCookieCSRFDefense(t *testing.T) {
	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	targetURL := "/api/v1/metrics?view=full"
	state, stateCookie, err := mgr.CreateStateCookie(targetURL)
	if err != nil {
		t.Fatalf("CreateStateCookie failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/callback?state="+state, nil)
	req.AddCookie(stateCookie)

	verifiedTarget, err := mgr.VerifyStateCookie(req, state)
	if err != nil {
		t.Fatalf("VerifyStateCookie failed on valid state: %v", err)
	}
	if verifiedTarget != targetURL {
		t.Errorf("Expected target URL %q, got %q", targetURL, verifiedTarget)
	}

	// State mismatch (CSRF attempt)
	_, err = mgr.VerifyStateCookie(req, "attacker-state-token")
	if err == nil {
		t.Error("Expected error on mismatched state parameter, but got nil")
	}

	// Open redirect attack prevention
	maliciousURLs := []string{
		"//evil.com/phishing",
		"http://evil.com/phishing",
		"https://evil.com/phishing",
		"",
	}

	for _, malURL := range maliciousURLs {
		t.Run("OpenRedirect_"+malURL, func(t *testing.T) {
			s, c, _ := mgr.CreateStateCookie(malURL)
			r := httptest.NewRequest("GET", "/callback?state="+s, nil)
			r.AddCookie(c)

			safeTarget, err := mgr.VerifyStateCookie(r, s)
			if err != nil {
				t.Fatalf("VerifyStateCookie failed: %v", err)
			}
			if safeTarget != "/" {
				t.Errorf("Expected open redirect URL %q to be sanitized to %q, got %q", malURL, "/", safeTarget)
			}
		})
	}
}

// TestOAuthUserWhitelisting verifies allowed users and allowed domains filtering.
func TestOAuthUserWhitelisting(t *testing.T) {
	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		AllowedUsers:   []string{"alice@example.com", "bob@corp.com"},
		AllowedDomains: []string{"trustedcompany.com"},
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	authorizedEmails := []string{
		"alice@example.com",
		"ALICE@EXAMPLE.COM", // case insensitive
		"bob@corp.com",
		"charlie@trustedcompany.com",
		"anyone@trustedcompany.com",
	}

	for _, email := range authorizedEmails {
		if !mgr.isUserAuthorized(email) {
			t.Errorf("Expected %s to be authorized, but was denied", email)
		}
	}

	unauthorizedEmails := []string{
		"eve@attacker.com",
		"mallory@example.org",
		"bob@othercorp.com",
	}

	for _, email := range unauthorizedEmails {
		if mgr.isUserAuthorized(email) {
			t.Errorf("Expected %s to be unauthorized, but was allowed", email)
		}
	}
}

// TestLoadAllowedUsersFromFile tests reading emails from allowed.txt file format.
func TestLoadAllowedUsersFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "allowed.txt")
	content := `# Allowed admin users
salikh@gmail.com
salikh@google.com # primary work email

# Other users
asuka.ujiie@gmail.com

`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test allowed file: %v", err)
	}

	users, err := LoadAllowedUsersFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadAllowedUsersFromFile failed: %v", err)
	}

	expected := []string{
		"salikh@gmail.com",
		"salikh@google.com",
		"asuka.ujiie@gmail.com",
	}

	if len(users) != len(expected) {
		t.Fatalf("Expected %d users, got %d: %v", len(expected), len(users), users)
	}

	for i, exp := range expected {
		if users[i] != exp {
			t.Errorf("User[%d] = %q, expected %q", i, users[i], exp)
		}
	}
}

// TestProxyEnforcesOAuthOnAllRequestsExceptACME verifies:
// 1. ACME challenge requests are exempt and NOT redirected to OAuth login.
// 2. Unauthenticated normal requests are redirected to Google OAuth login.
// 3. Authenticated requests pass to backend with identity headers.
func TestProxyEnforcesOAuthOnAllRequestsExceptACME(t *testing.T) {
	// Create mock backend
	backendReceivedHeaders := make(http.Header)
	backendReceivedPath := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReceivedPath = r.URL.Path
		for k, v := range r.Header {
			backendReceivedHeaders[k] = v
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "backend ok")
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := NewHTTPSProxy(backendURL, nil, false)

	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}
	proxy.SetOAuthManager(mgr)

	// 1. ACME Challenge request: MUST BYPASS OAuth completely!
	acmeReq := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-challenge-token", nil)
	acmeW := httptest.NewRecorder()
	proxy.serveProxy(acmeW, acmeReq)

	if acmeW.Code != http.StatusOK {
		t.Fatalf("Expected ACME challenge to return 200 from backend, got %d", acmeW.Code)
	}
	if backendReceivedPath != "/.well-known/acme-challenge/test-challenge-token" {
		t.Errorf("Expected ACME path to reach backend, got %s", backendReceivedPath)
	}

	// 2. Unauthenticated request to /dashboard: MUST REDIRECT to Google login (302)
	unauthReq := httptest.NewRequest("GET", "/dashboard?tab=overview", nil)
	unauthW := httptest.NewRecorder()
	proxy.serveProxy(unauthW, unauthReq)

	if unauthW.Code != http.StatusFound {
		t.Fatalf("Expected unauthenticated request to return 302 Found redirect, got %d", unauthW.Code)
	}
	loc := unauthW.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/auth") {
		t.Errorf("Expected redirect to Google Auth URL, got %s", loc)
	}
	// Verify state cookie was set
	stateCookieFound := false
	for _, c := range unauthW.Result().Cookies() {
		if c.Name == DefaultStateCookieName {
			stateCookieFound = true
			break
		}
	}
	if !stateCookieFound {
		t.Error("Expected state cookie to be set in redirect response")
	}

	// 3. Authenticated request with valid session cookie: MUST FORWARD to backend with headers
	authReq := httptest.NewRequest("GET", "/api/data", nil)
	authReq.AddCookie(mgr.CreateSessionCookie("salikh@google.com"))
	authW := httptest.NewRecorder()
	proxy.serveProxy(authW, authReq)

	if authW.Code != http.StatusOK {
		t.Fatalf("Expected authenticated request to return 200 OK, got %d", authW.Code)
	}
	if backendReceivedHeaders.Get("X-Forwarded-User") != "salikh@google.com" {
		t.Errorf("Expected X-Forwarded-User to be salikh@google.com, got %q", backendReceivedHeaders.Get("X-Forwarded-User"))
	}
	if backendReceivedHeaders.Get("X-Auth-Email") != "salikh@google.com" {
		t.Errorf("Expected X-Auth-Email to be salikh@google.com, got %q", backendReceivedHeaders.Get("X-Auth-Email"))
	}
}

// TestFullOAuthCallbackFlow tests the end-to-end OAuth callback exchange with a mock OAuth provider.
func TestFullOAuthCallbackFlow(t *testing.T) {
	// Mock Google OAuth Token and UserInfo Server
	mockOAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			code := r.Form.Get("code")
			if code != "valid-test-code" {
				http.Error(w, "invalid code", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token-xyz",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer mock-access-token-xyz" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(GoogleUserInfo{
				Sub:           "google-sub-12345",
				Email:         "user@example.com",
				EmailVerified: true,
				Name:          "Test User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOAuthServer.Close()

	// Create manager configured with mock server
	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		UserInfoURL: mockOAuthServer.URL + "/userinfo",
		HTTPClient:  mockOAuthServer.Client(),
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	// Override token endpoint for test
	mgr.config.Endpoint = oauth2.Endpoint{
		AuthURL:  mockOAuthServer.URL + "/auth",
		TokenURL: mockOAuthServer.URL + "/token",
	}

	// 1. Generate state cookie for target URL /profile
	state, stateCookie, err := mgr.CreateStateCookie("/profile?section=billing")
	if err != nil {
		t.Fatalf("CreateStateCookie failed: %v", err)
	}

	// 2. Perform callback
	cbReq := httptest.NewRequest("GET", fmt.Sprintf("/callback?code=valid-test-code&state=%s", state), nil)
	cbReq.AddCookie(stateCookie)
	cbW := httptest.NewRecorder()

	mgr.HandleCallback(cbW, cbReq)

	if cbW.Code != http.StatusFound {
		t.Fatalf("Expected callback status 302 Found, got %d: %s", cbW.Code, cbW.Body.String())
	}

	// Verify redirect location is the original target URL
	loc := cbW.Header().Get("Location")
	if loc != "/profile?section=billing" {
		t.Errorf("Expected redirect to /profile?section=billing, got %s", loc)
	}

	// Verify session cookie was set
	cookies := cbW.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DefaultSessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("Expected session cookie to be set in callback response")
	}

	// Verify session cookie is valid for user@example.com
	reqWithSession := httptest.NewRequest("GET", "/profile", nil)
	reqWithSession.AddCookie(sessionCookie)
	user, err := mgr.AuthenticateRequest(reqWithSession)
	if err != nil {
		t.Fatalf("AuthenticateRequest failed with callback session cookie: %v", err)
	}
	if user != "user@example.com" {
		t.Errorf("Expected authenticated user user@example.com, got %s", user)
	}
}

// TestSanitizeURI verifies that sensitive OAuth query parameters are masked in log strings.
func TestSanitizeURI(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "/callback?code=secret_code_123&state=my_state_456",
			expected: "/callback?code=%5BREDACTED%5D&state=%5BREDACTED%5D",
		},
		{
			input:    "/api/users?page=1&limit=20",
			expected: "/api/users?page=1&limit=20",
		},
		{
			input:    "/token?client_secret=super_secret_xyz",
			expected: "/token?client_secret=%5BREDACTED%5D",
		},
	}

	for _, tc := range testCases {
		sanitized := sanitizeURI(tc.input)
		if sanitized != tc.expected {
			t.Errorf("sanitizeURI(%q) = %q, expected %q", tc.input, sanitized, tc.expected)
		}
	}
}

// TestOAuthRedirectURLUsesHostnameFlag verifies that the OAuth redirect URL is set correctly based on the hostname parameter.
func TestOAuthRedirectURLUsesHostnameFlag(t *testing.T) {
	testHostname := "example.com"

	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		Hostname:     testHostname,
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	expectedURL := "https://example.com/callback"
	if mgr.config.RedirectURL != expectedURL {
		t.Errorf("Expected redirect URL %q, got %q", expectedURL, mgr.config.RedirectURL)
	}
}

// TestOAuthRedirectURLWithCustomCallbackPath verifies that custom callback paths are respected.
func TestOAuthRedirectURLWithCustomCallbackPath(t *testing.T) {
	testHostname := "example.com"
	testCallbackPath := "/oauth2/callback"

	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		Hostname:     testHostname,
		CallbackPath: testCallbackPath,
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	expectedURL := "https://example.com/oauth2/callback"
	if mgr.config.RedirectURL != expectedURL {
		t.Errorf("Expected redirect URL %q, got %q", expectedURL, mgr.config.RedirectURL)
	}
}

// TestOAuthVirtualHostRedirectURL verifies dynamic redirect URLs for virtual hosts.
func TestOAuthVirtualHostRedirectURL(t *testing.T) {
	primaryHostname := "api.example.com"
	virtualHostnames := []string{"web.example.com", "admin.example.com"}

	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		Hostname:         primaryHostname,
		VirtualHostnames: virtualHostnames,
		SecureCookie:     false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	testCases := []struct {
		incomingHost    string
		expectedRedirectURL string
		description     string
	}{
		{
			"api.example.com",
			"https://api.example.com/callback",
			"Primary hostname should use primary redirect URL",
		},
		{
			"web.example.com",
			"https://web.example.com/callback",
			"Virtual hostname should use its own redirect URL",
		},
		{
			"admin.example.com",
			"https://admin.example.com/callback",
			"Another virtual hostname should use its own redirect URL",
		},
		{
			"web.example.com:8080",
			"https://web.example.com/callback",
			"Virtual hostname with port should strip port in redirect URL",
		},
		{
			"unknown.example.com",
			"https://api.example.com/callback",
			"Unknown hostname should fall back to primary redirect URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/callback", nil)
			req.Host = tc.incomingHost

			redirectURL := mgr.getRedirectURLForRequest(req)
			if redirectURL != tc.expectedRedirectURL {
				t.Errorf("Expected redirect URL %q, got %q", tc.expectedRedirectURL, redirectURL)
			}
		})
	}
}

// TestOAuthLoginRedirectWithVirtualHost verifies login redirect uses correct hostname.
func TestOAuthLoginRedirectWithVirtualHost(t *testing.T) {
	primaryHostname := "api.example.com"
	virtualHostnames := []string{"web.example.com"}

	mgr, err := NewOAuthManager([]byte(sampleGoogleSecretJSON), OAuthOptions{
		Hostname:         primaryHostname,
		VirtualHostnames: virtualHostnames,
		SecureCookie:     false,
	})
	if err != nil {
		t.Fatalf("NewOAuthManager failed: %v", err)
	}

	testCases := []struct {
		incomingHost         string
		shouldContainInAuthURL string
		description          string
	}{
		{
			"web.example.com",
			"https://web.example.com/callback",
			"Login from virtual host should use that hostname in auth URL",
		},
		{
			"api.example.com",
			"https://api.example.com/callback",
			"Login from primary host should use primary hostname in auth URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Host = tc.incomingHost
			w := httptest.NewRecorder()

			mgr.HandleLoginRedirect(w, req)

			if w.Code != http.StatusFound {
				t.Fatalf("Expected 302 redirect, got %d", w.Code)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, tc.shouldContainInAuthURL) {
				t.Errorf("Expected auth URL to contain %q, got %q", tc.shouldContainInAuthURL, location)
			}
		})
	}
}
