package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/term"
)

const (
	// EncryptedHeaderMagic is the prefix for AES-256-GCM encrypted secret files.
	EncryptedHeaderMagic = "OAUTH_ENC_V1\n"
	SaltLength           = 16
	NonceLength          = 12
	PBKDF2Iterations     = 100000
	KeyLength            = 32

	DefaultSessionCookieName = "_proxy_session"
	DefaultStateCookieName   = "_proxy_oauth_state"
	DefaultSessionDuration   = 24 * time.Hour
	DefaultStateDuration     = 10 * time.Minute
	DefaultGoogleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// GoogleUserInfo represents the user profile response from Google's userinfo endpoint.
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// OAuthOptions configures the OAuthManager behavior.
type OAuthOptions struct {
	CookieSecret      []byte
	CookieName        string
	SessionDuration   time.Duration
	AllowedUsers      []string
	AllowedDomains    []string
	CallbackPath      string
	UserInfoURL       string
	Hostname          string
	VirtualHostnames  []string // Additional hostnames for virtual host support
	HTTPClient        *http.Client
	SecureCookie      bool
	Verbose           bool
}

// OAuthManager handles Google OAuth 2.0 authentication, session cookies, and state verification.
type OAuthManager struct {
	config           *oauth2.Config
	cookieSecret     []byte
	cookieName       string
	stateCookieName  string
	sessionDuration  time.Duration
	allowedUsers     map[string]bool
	allowedDomains   []string
	callbackPath     string
	logoutPath       string
	userInfoURL      string
	httpClient       *http.Client
	secureCookie     bool
	verbose          bool
	virtualHostnames map[string]bool // Set of allowed hostnames for OAuth callbacks
}

// EncryptSecret encrypts plaintext using AES-256-GCM with a PBKDF2-derived key.
func EncryptSecret(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iterations, KeyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(EncryptedHeaderMagic))

	var buf bytes.Buffer
	buf.WriteString(EncryptedHeaderMagic)
	buf.Write(salt)
	buf.Write(nonce)
	buf.Write(ciphertext)

	return buf.Bytes(), nil
}

// DecryptSecret decrypts data produced by EncryptSecret using AES-256-GCM.
func DecryptSecret(encryptedData []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	magicLen := len(EncryptedHeaderMagic)
	if len(encryptedData) < magicLen+SaltLength+NonceLength {
		return nil, fmt.Errorf("invalid encrypted secret: file is too short")
	}

	if string(encryptedData[:magicLen]) != EncryptedHeaderMagic {
		return nil, fmt.Errorf("invalid encrypted secret header: expected %q", strings.TrimSpace(EncryptedHeaderMagic))
	}

	salt := encryptedData[magicLen : magicLen+SaltLength]
	nonce := encryptedData[magicLen+SaltLength : magicLen+SaltLength+NonceLength]
	ciphertext := encryptedData[magicLen+SaltLength+NonceLength:]

	key := pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iterations, KeyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(EncryptedHeaderMagic))
	if err != nil {
		return nil, fmt.Errorf("decryption failed (incorrect passphrase or corrupted file): %w", err)
	}

	return plaintext, nil
}

// LoadOAuthSecret loads OAuth secret JSON data from an environment variable or file.
// If reading from disk, it checks and enforces restrictive file permissions (0600)
// and handles decryption if the file is encrypted.
func LoadOAuthSecret(secretPath string, passphrase string) ([]byte, error) {
	// 1. Check OAUTH_SECRET_JSON environment variable (zero-disk option)
	if envSecret := os.Getenv("OAUTH_SECRET_JSON"); envSecret != "" {
		log.Printf("Loaded OAuth secret directly from OAUTH_SECRET_JSON environment variable")
		return []byte(envSecret), nil
	}

	if secretPath == "" {
		secretPath = "secret.json"
	}

	// If secretPath does not exist, check if secretPath.enc exists
	if _, err := os.Stat(secretPath); os.IsNotExist(err) {
		encPath := secretPath + ".enc"
		if _, errEnc := os.Stat(encPath); errEnc == nil {
			secretPath = encPath
		} else {
			return nil, fmt.Errorf("OAuth secret file not found at %s (also checked %s)", secretPath, encPath)
		}
	}

	// 2. Check and secure file permissions on disk
	info, err := os.Stat(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect OAuth secret file %s: %w", secretPath, err)
	}

	if info.Mode().Perm()&0077 != 0 {
		log.Printf("SECURITY NOTICE: OAuth secret file %s had insecure permissions (%04o). Tightening to 0600 (owner only)...", secretPath, info.Mode().Perm())
		if err := os.Chmod(secretPath, 0600); err != nil {
			log.Printf("WARNING: Failed to tighten file permissions on %s: %v", secretPath, err)
		} else {
			log.Printf("Successfully tightened file permissions on %s to 0600", secretPath)
		}
	}

	data, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OAuth secret file %s: %w", secretPath, err)
	}

	// 3. Check if file is encrypted
	isEncrypted := strings.HasPrefix(string(data), EncryptedHeaderMagic) || strings.HasSuffix(secretPath, ".enc")
	if isEncrypted {
		if passphrase == "" {
			passphrase = os.Getenv("OAUTH_PASSPHRASE")
		}

		if passphrase == "" {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("Enter passphrase to decrypt %s: ", filepath.Base(secretPath))
				bytePass, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return nil, fmt.Errorf("failed to read passphrase: %w", err)
				}
				passphrase = string(bytePass)
			} else {
				return nil, fmt.Errorf("OAuth secret file %s is encrypted, but no passphrase was provided (use --oauth-passphrase or OAUTH_PASSPHRASE env var)", secretPath)
			}
		}

		decrypted, err := DecryptSecret(data, passphrase)
		if err != nil {
			return nil, err
		}
		log.Printf("Successfully decrypted OAuth secret file: %s", secretPath)
		return decrypted, nil
	}

	// Plaintext file loaded
	log.Printf("Loaded plaintext OAuth secret from %s", secretPath)
	log.Printf("TIP: You can protect this secret by encrypting it with: ./https-proxy -encrypt-secret %s", secretPath)
	return data, nil
}

// LoadAllowedUsersFromFile reads allowed user email addresses from a text file (one per line).
// Blank lines and lines starting with '#' are ignored.
func LoadAllowedUsersFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read allowed users file %s: %w", filePath, err)
	}

	var users []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			users = append(users, strings.ToLower(line))
		}
	}

	return users, nil
}

// NewOAuthManager creates a new OAuthManager from raw Google OAuth client secret JSON.
func NewOAuthManager(secretJSON []byte, opts OAuthOptions) (*OAuthManager, error) {
	// Parse Google client credentials JSON
	cfg, err := google.ConfigFromJSON(secretJSON,
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Google OAuth client credentials JSON: %w", err)
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("OAuth secret JSON must contain non-empty client_id and client_secret")
	}

	callbackPath := opts.CallbackPath
	if callbackPath == "" {
		if cfg.RedirectURL != "" {
			if parsed, err := url.Parse(cfg.RedirectURL); err == nil && parsed.Path != "" {
				callbackPath = parsed.Path
			}
		}
		if callbackPath == "" {
			callbackPath = "/callback"
		}
	}

	if opts.Hostname != "" {
		cfg.RedirectURL = "https://" + opts.Hostname + callbackPath
	}

	// Derive cookie signing key securely from client secret if not explicitly provided
	cookieSecret := opts.CookieSecret
	if len(cookieSecret) == 0 {
		h := hmac.New(sha256.New, []byte(cfg.ClientSecret))
		h.Write([]byte("https-proxy-cookie-secret-v1"))
		cookieSecret = h.Sum(nil)
	}

	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = DefaultSessionCookieName
	}

	sessionDuration := opts.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = DefaultSessionDuration
	}

	userInfoURL := opts.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = DefaultGoogleUserInfoURL
	}

	allowedUsersMap := make(map[string]bool)
	for _, u := range opts.AllowedUsers {
		u = strings.ToLower(strings.TrimSpace(u))
		if u != "" {
			allowedUsersMap[u] = true
		}
	}

	var allowedDomains []string
	for _, d := range opts.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "@")
		if d != "" {
			allowedDomains = append(allowedDomains, d)
		}
	}

	virtualHostnames := make(map[string]bool)
	if opts.Hostname != "" {
		virtualHostnames[strings.ToLower(opts.Hostname)] = true
	}
	for _, h := range opts.VirtualHostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			virtualHostnames[h] = true
		}
	}

	mgr := &OAuthManager{
		config:           cfg,
		cookieSecret:     cookieSecret,
		cookieName:       cookieName,
		stateCookieName:  DefaultStateCookieName,
		sessionDuration:  sessionDuration,
		allowedUsers:     allowedUsersMap,
		allowedDomains:   allowedDomains,
		callbackPath:     callbackPath,
		logoutPath:       "/oauth/logout",
		userInfoURL:      userInfoURL,
		httpClient:       opts.HTTPClient,
		secureCookie:     opts.SecureCookie,
		verbose:          opts.Verbose,
		virtualHostnames: virtualHostnames,
	}

	return mgr, nil
}

// sign generates an HMAC-SHA256 hex signature for the given payload.
func (m *OAuthManager) sign(data string) string {
	h := hmac.New(sha256.New, m.cookieSecret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// verifySignature checks if the provided signature matches the HMAC-SHA256 of data.
func (m *OAuthManager) verifySignature(data, sigHex string) bool {
	expectedSig := m.sign(data)
	return hmac.Equal([]byte(sigHex), []byte(expectedSig))
}

// isUserAuthorized checks whether an authenticated email is permitted by whitelists.
func (m *OAuthManager) isUserAuthorized(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(m.allowedUsers) == 0 && len(m.allowedDomains) == 0 {
		return true // Allow all authenticated accounts if no whitelist is specified
	}

	if m.allowedUsers[email] {
		return true
	}

	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		domain := parts[1]
		for _, allowedDomain := range m.allowedDomains {
			if strings.EqualFold(domain, allowedDomain) {
				return true
			}
		}
	}

	return false
}

// CreateSessionCookie generates a signed HTTP session cookie for an authenticated email.
func (m *OAuthManager) CreateSessionCookie(email string) *http.Cookie {
	expiry := time.Now().Add(m.sessionDuration).Unix()
	payload := fmt.Sprintf("%s:%d", email, expiry)
	sig := m.sign(payload)
	value := fmt.Sprintf("%s:%s", payload, sig)

	return &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.sessionDuration.Seconds()),
	}
}

// ClearSessionCookie creates an expired session cookie to log the user out.
func (m *OAuthManager) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// AuthenticateRequest verifies the session cookie and returns the user email if valid.
func (m *OAuthManager) AuthenticateRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return "", fmt.Errorf("no session cookie")
	}

	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed session cookie")
	}

	email := parts[0]
	expiryStr := parts[1]
	sig := parts[2]

	payload := fmt.Sprintf("%s:%s", email, expiryStr)
	if !m.verifySignature(payload, sig) {
		return "", fmt.Errorf("invalid cookie signature")
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", fmt.Errorf("session expired")
	}

	if !m.isUserAuthorized(email) {
		return "", fmt.Errorf("user %s is not authorized", email)
	}

	return email, nil
}

// CreateStateCookie generates a secure random state token and signed state cookie.
func (m *OAuthManager) CreateStateCookie(targetURL string) (string, *http.Cookie, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("failed to generate random state: %w", err)
	}
	state := hex.EncodeToString(b)
	expiry := time.Now().Add(DefaultStateDuration).Unix()

	// Sanitize targetURL to prevent open redirect vulnerabilities
	if targetURL == "" || !strings.HasPrefix(targetURL, "/") || strings.HasPrefix(targetURL, "//") {
		targetURL = "/"
	}

	targetEncoded := base64.RawURLEncoding.EncodeToString([]byte(targetURL))
	payload := fmt.Sprintf("%s:%s:%d", state, targetEncoded, expiry)
	sig := m.sign(payload)
	value := fmt.Sprintf("%s:%s", payload, sig)

	cookie := &http.Cookie{
		Name:     m.stateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(DefaultStateDuration.Seconds()),
	}

	return state, cookie, nil
}

// ClearStateCookie creates an expired state cookie to clean up after callback.
func (m *OAuthManager) ClearStateCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// VerifyStateCookie verifies the state parameter against the state cookie and returns target URL.
func (m *OAuthManager) VerifyStateCookie(r *http.Request, stateParam string) (string, error) {
	if stateParam == "" {
		return "", fmt.Errorf("missing state parameter in OAuth response")
	}

	cookie, err := r.Cookie(m.stateCookieName)
	if err != nil {
		return "", fmt.Errorf("missing state cookie in request")
	}

	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("malformed state cookie")
	}

	cookieState := parts[0]
	targetEncoded := parts[1]
	expiryStr := parts[2]
	sig := parts[3]

	payload := fmt.Sprintf("%s:%s:%s", cookieState, targetEncoded, expiryStr)
	if !m.verifySignature(payload, sig) {
		return "", fmt.Errorf("invalid state cookie signature")
	}

	if cookieState != stateParam {
		return "", fmt.Errorf("state mismatch (possible CSRF attempt)")
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", fmt.Errorf("state cookie expired")
	}

	targetBytes, err := base64.RawURLEncoding.DecodeString(targetEncoded)
	if err != nil {
		return "/", nil
	}
	targetURL := string(targetBytes)
	if !strings.HasPrefix(targetURL, "/") || strings.HasPrefix(targetURL, "//") {
		targetURL = "/"
	}

	return targetURL, nil
}

// IsCallback returns true if the request matches the OAuth callback path.
func (m *OAuthManager) IsCallback(r *http.Request) bool {
	return r.URL.Path == m.callbackPath
}

// IsLogout returns true if the request matches the logout path.
func (m *OAuthManager) IsLogout(r *http.Request) bool {
	return r.URL.Path == m.logoutPath
}

// getRedirectURLForRequest returns the appropriate OAuth redirect URL for the incoming request.
// If the request hostname matches a configured virtual hostname, that hostname is used.
// Otherwise, the default configured hostname is used.
func (m *OAuthManager) getRedirectURLForRequest(r *http.Request) string {
	requestHost := r.Host
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		requestHost = h
	}
	requestHost = strings.ToLower(requestHost)

	// Check if the request hostname is in our virtual hosts
	if m.virtualHostnames[requestHost] {
		return "https://" + requestHost + m.callbackPath
	}

	// Fallback to the default hostname from config
	return m.config.RedirectURL
}

// HandleLoginRedirect redirects unauthenticated requests to the Google OAuth login page.
func (m *OAuthManager) HandleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	targetURI := r.URL.RequestURI()
	if targetURI == "" {
		targetURI = "/"
	}

	state, stateCookie, err := m.CreateStateCookie(targetURI)
	if err != nil {
		http.Error(w, "Failed to initiate login", http.StatusInternalServerError)
		return
	}

	// Get the appropriate redirect URL for this request
	redirectURL := m.getRedirectURLForRequest(r)

	// Create a temporary config with the request-specific redirect URL for this login flow
	tempConfig := *m.config
	tempConfig.RedirectURL = redirectURL

	http.SetCookie(w, stateCookie)
	authURL := tempConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// fetchUserInfo retrieves user profile information from Google.
func (m *OAuthManager) fetchUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
	var client *http.Client
	if m.httpClient != nil {
		client = m.httpClient
	} else {
		client = m.config.Client(ctx, token)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", m.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo request returned status %d: %s", resp.StatusCode, string(body))
	}

	var info GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return &info, nil
}

// HandleCallback handles the Google OAuth 2.0 authorization callback.
func (m *OAuthManager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for error response from OAuth provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("[oauth] OAuth provider returned error: %s", errParam)
		http.Error(w, fmt.Sprintf("OAuth error: %s", errParam), http.StatusForbidden)
		return
	}

	// Verify state parameter against state cookie
	targetURL, err := m.VerifyStateCookie(r, r.URL.Query().Get("state"))
	if err != nil {
		log.Printf("[oauth] State verification failed: %v", err)
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("[oauth] Missing code parameter in callback")
		http.Error(w, "Bad Request: missing code parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if m.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, m.httpClient)
	}

	// Get the appropriate redirect URL for this callback request (must match the login flow)
	redirectURL := m.getRedirectURLForRequest(r)

	// Create a temporary config with the request-specific redirect URL
	// This is necessary because Google validates that the redirect_uri in the token exchange
	// matches what was used in the authorization request
	tempConfig := *m.config
	tempConfig.RedirectURL = redirectURL

	// Exchange authorization code for token
	token, err := tempConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("[oauth] Token exchange failed: %v", err)
		http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Retrieve user identity
	userInfo, err := m.fetchUserInfo(ctx, token)
	if err != nil {
		log.Printf("[oauth] User info retrieval failed: %v", err)
		http.Error(w, "Failed to retrieve user information: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !userInfo.EmailVerified {
		log.Printf("[oauth] Rejected login for %s: email not verified", userInfo.Email)
		http.Error(w, "Forbidden: Google email address is unverified", http.StatusForbidden)
		return
	}

	if !m.isUserAuthorized(userInfo.Email) {
		log.Printf("[oauth] Access denied for unauthorized user: %s", userInfo.Email)
		http.Error(w, fmt.Sprintf("Forbidden: user %s is not authorized to access this service", userInfo.Email), http.StatusForbidden)
		return
	}

	if m.verbose {
		log.Printf("[oauth] Successfully authenticated user: %s", userInfo.Email)
	}

	// Set session cookie and clear state cookie
	http.SetCookie(w, m.CreateSessionCookie(userInfo.Email))
	http.SetCookie(w, m.ClearStateCookie())

	// Redirect to the originally requested destination
	http.Redirect(w, r, targetURL, http.StatusFound)
}

// HandleLogout clears the session cookie and logs the user out.
func (m *OAuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, m.ClearSessionCookie())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `<!DOCTYPE html><html><head><title>Logged Out</title></head><body><h1>Logged Out</h1><p>You have been safely logged out.</p><p><a href="/">Log in again</a></p></body></html>`)
}

// sanitizeURI redacts sensitive query parameters (code, state, secrets) from URLs for logging.
func sanitizeURI(uri string) string {
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	sensitiveParams := []string{"code", "state", "token", "access_token", "refresh_token", "client_secret", "secret"}
	modified := false
	for _, param := range sensitiveParams {
		if q.Has(param) {
			q.Set(param, "[REDACTED]")
			modified = true
		}
	}
	if modified {
		u.RawQuery = q.Encode()
		return u.String()
	}
	return uri
}

// handleEncryptSecretCLI handles the -encrypt-secret CLI command.
func handleEncryptSecretCLI(inputPath, outputPath, passphrase string) {
	if outputPath == "" {
		outputPath = inputPath + ".enc"
	}

	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		log.Fatalf("Failed to read input secret file %s: %v", inputPath, err)
	}

	var dummy map[string]interface{}
	if err := json.Unmarshal(plaintext, &dummy); err != nil {
		log.Printf("Warning: %s does not appear to be valid JSON (%v)", inputPath, err)
	}

	if passphrase == "" {
		passphrase = os.Getenv("OAUTH_PASSPHRASE")
	}

	if passphrase == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			log.Fatal("Passphrase must be provided via -oauth-passphrase or OAUTH_PASSPHRASE env var in non-interactive mode")
		}
		fmt.Print("Enter passphrase to encrypt OAuth secret: ")
		bytePass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v", err)
		}
		fmt.Print("Confirm passphrase: ")
		confirmPass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read confirm passphrase: %v", err)
		}
		if string(bytePass) != string(confirmPass) {
			log.Fatal("Passphrases do not match")
		}
		passphrase = string(bytePass)
	}

	encrypted, err := EncryptSecret(plaintext, passphrase)
	if err != nil {
		log.Fatalf("Failed to encrypt secret: %v", err)
	}

	if err := os.WriteFile(outputPath, encrypted, 0600); err != nil {
		log.Fatalf("Failed to write encrypted secret to %s: %v", outputPath, err)
	}

	log.Printf("✓ Successfully encrypted %s -> %s (permissions 0600)", inputPath, outputPath)
	log.Printf("✓ You can now safely remove plaintext %s or store it in a secure password manager.", inputPath)
	log.Printf("To run the proxy with your encrypted credentials:")
	log.Printf("  ./https-proxy --oauth --oauth-secret=%s [other options]", outputPath)
	os.Exit(0)
}
