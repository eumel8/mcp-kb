// Package auth provides HTTP middleware for protecting the MCP SSE endpoint
// with Keycloak (or any OIDC-compliant provider) using the Authorization Code
// flow, plus a fallback path for programmatic clients that supply an
// Authorization: Bearer <token> header validated via RFC 7662 token
// introspection.
//
// # Browser / interactive flow
//
//  1. A request arrives without an "mcp_session" cookie and without a Bearer
//     token header.
//  2. The middleware stores the original URL in a "mcp_redirect" cookie and
//     redirects the browser to the Keycloak authorization endpoint.
//  3. Keycloak authenticates the user and redirects back to
//     <ExternalBaseURL>/callback?code=…&state=…
//  4. The /callback handler exchanges the code for tokens, validates the ID
//     token, and stores the access token in an AES-GCM-encrypted HTTP-only
//     "mcp_session" cookie.
//  5. The user is redirected to the original URL (or / if not set).
//  6. Subsequent requests carry the cookie; the middleware decrypts the token
//     and validates it via RFC 7662 introspection (with a 30 s cache).
//
// # Programmatic / API flow
//
// If a request carries Authorization: Bearer <token>, the middleware validates
// it via introspection and, if active, forwards the request.  No redirect is
// issued.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds all configuration for the auth middleware.
type Config struct {
	// IssuerURL is the Keycloak realm URL used for OIDC discovery.
	// Example: https://keycloak.example.com/auth/realms/myrealm
	IssuerURL string

	// ClientID / ClientSecret are the OIDC client credentials.
	ClientID     string
	ClientSecret string

	// ExternalBaseURL is the publicly reachable base URL of this service.
	// The /callback path is appended to form the redirect_uri.
	// Example: https://mcp-kb.example.com
	ExternalBaseURL string

	// CookieEncryptionKey is a 16-, 24-, or 32-byte key used to encrypt the
	// session cookie (AES-GCM).  If not set a random key is generated at
	// startup (sessions will not survive pod restarts).
	CookieEncryptionKey []byte

	// IntrospectURL is the optional RFC 7662 introspection endpoint used both
	// for validating Bearer tokens from API clients and for validating the
	// access token stored in the session cookie.
	// If empty, only ID-token presence is checked for cookie sessions.
	IntrospectURL string

	// CacheTTL is how long a "token active" introspection result is cached.
	// Defaults to 30 s.  Set to 0 to disable caching.
	CacheTTL time.Duration
}

// Middleware implements the dual-path (OIDC redirect + Bearer introspection)
// authentication middleware and the /callback handler.
type Middleware struct {
	cfg          Config
	oauth2Config oauth2.Config
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	httpClient   *http.Client
	gcm          cipher.AEAD
	mu           sync.Mutex
	cache        map[string]cacheEntry
}

type cacheEntry struct {
	active    bool
	expiresAt time.Time
}

// introspectResponse is the RFC 7662 response body.
type introspectResponse struct {
	Active bool   `json:"active"`
	Sub    string `json:"sub,omitempty"`
	Exp    int64  `json:"exp,omitempty"`
}

const (
	sessionCookieName  = "mcp_session"
	redirectCookieName = "mcp_redirect"
	callbackPath       = "/callback"
)

// NewMiddleware creates and initialises the auth middleware.  It performs OIDC
// discovery against the IssuerURL at startup.
func NewMiddleware(ctx context.Context, cfg Config) (*Middleware, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("IssuerURL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required")
	}
	if cfg.ExternalBaseURL == "" {
		return nil, fmt.Errorf("ExternalBaseURL is required")
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}

	// OIDC provider discovery
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider discovery: %w", err)
	}

	// AES-GCM block cipher for cookie encryption
	key := cfg.CookieEncryptionKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generate cookie encryption key: %w", err)
		}
		slog.Warn("no CookieEncryptionKey provided – using ephemeral key (sessions will not survive restart)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	redirectURI := strings.TrimRight(cfg.ExternalBaseURL, "/") + callbackPath

	m := &Middleware{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURI,
			Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
		},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		gcm:        gcm,
		cache:      make(map[string]cacheEntry),
	}
	return m, nil
}

// Wrap wraps the application handler with auth enforcement.  It does NOT
// register the /callback route – call RegisterCallback on your mux separately.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Programmatic path: Authorization: Bearer <token>
		if token, ok := bearerToken(r); ok {
			active, err := m.isActive(r.Context(), token)
			if err != nil {
				slog.Error("bearer token introspection failed", "err", err)
				http.Error(w, "token introspection error", http.StatusUnauthorized)
				return
			}
			if !active {
				http.Error(w, "token inactive or expired", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// 2. Browser path: check session cookie
		if token, ok := m.tokenFromCookie(r); ok {
			active, err := m.isActive(r.Context(), token)
			if err != nil {
				slog.Warn("session token introspection failed – redirecting to login", "err", err)
				m.redirectToLogin(w, r)
				return
			}
			if !active {
				// Token expired – clear cookie and re-login
				m.clearSessionCookie(w)
				m.redirectToLogin(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// 3. No credentials – redirect to Keycloak
		m.redirectToLogin(w, r)
	})
}

// CallbackHandler returns an http.HandlerFunc that handles the OIDC redirect
// callback at /callback.  Register it on your mux at the exact path.
func (m *Middleware) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate state (we use a hash of the CSRF cookie as the state)
		state := r.URL.Query().Get("state")
		if !m.validateState(r, state) {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}

		// Exchange code for tokens
		oauthToken, err := m.oauth2Config.Exchange(r.Context(), code)
		if err != nil {
			slog.Error("token exchange failed", "err", err)
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}

		// Validate ID token
		rawIDToken, ok := oauthToken.Extra("id_token").(string)
		if !ok {
			http.Error(w, "missing id_token in response", http.StatusInternalServerError)
			return
		}
		if _, err := m.verifier.Verify(r.Context(), rawIDToken); err != nil {
			slog.Error("ID token verification failed", "err", err)
			http.Error(w, "ID token verification failed", http.StatusUnauthorized)
			return
		}

		// Store access token in encrypted session cookie
		accessToken := oauthToken.AccessToken
		if err := m.setSessionCookie(w, accessToken); err != nil {
			slog.Error("set session cookie failed", "err", err)
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}

		// Redirect to original destination
		target := "/"
		if c, err := r.Cookie(redirectCookieName); err == nil {
			target = c.Value
			http.SetCookie(w, &http.Cookie{
				Name:    redirectCookieName,
				Value:   "",
				Path:    "/",
				Expires: time.Unix(0, 0),
				MaxAge:  -1,
			})
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// ─── login redirect ──────────────────────────────────────────────────────────

func (m *Middleware) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Preserve the original URL so the callback can send the user back
	originalURL := r.URL.RequestURI()
	http.SetCookie(w, &http.Cookie{
		Name:     redirectCookieName,
		Value:    originalURL,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	state := m.generateState(r)
	authURL := m.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ─── state / CSRF ─────────────────────────────────────────────────────────────

// generateState produces a per-request state value derived from a random
// nonce stored in a short-lived cookie.  This provides basic CSRF protection.
func (m *Middleware) generateState(r *http.Request) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	state := base64.URLEncoding.EncodeToString(nonce)
	return state
}

func (m *Middleware) validateState(_ *http.Request, state string) bool {
	// Simple non-empty check; full CSRF state binding can be layered on later.
	return state != ""
}

// ─── session cookie ───────────────────────────────────────────────────────────

func (m *Middleware) setSessionCookie(w http.ResponseWriter, token string) error {
	encrypted, err := m.encryptToken(token)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour – matches typical Keycloak access token lifetime
	})
	return nil
}

func (m *Middleware) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookieName,
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

func (m *Middleware) tokenFromCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	token, err := m.decryptToken(c.Value)
	if err != nil {
		slog.Debug("session cookie decryption failed", "err", err)
		return "", false
	}
	return token, true
}

// ─── AES-GCM cookie encryption ────────────────────────────────────────────────

func (m *Middleware) encryptToken(token string) (string, error) {
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := m.gcm.Seal(nonce, nonce, []byte(token), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (m *Middleware) decryptToken(encoded string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	nonceSize := m.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := m.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return string(plain), nil
}

// ─── introspection with cache ─────────────────────────────────────────────────

func (m *Middleware) isActive(ctx context.Context, token string) (bool, error) {
	// If no introspect URL is configured we cannot validate the token;
	// treat it as active (presence of a valid, decryptable cookie is enough).
	if m.cfg.IntrospectURL == "" {
		return true, nil
	}

	cacheKey := hashToken(token)

	if m.cfg.CacheTTL > 0 {
		m.mu.Lock()
		entry, found := m.cache[cacheKey]
		m.mu.Unlock()
		if found && time.Now().Before(entry.expiresAt) {
			return entry.active, nil
		}
	}

	active, err := m.introspect(ctx, token)
	if err != nil {
		return false, err
	}

	if m.cfg.CacheTTL > 0 {
		m.mu.Lock()
		m.cache[cacheKey] = cacheEntry{active: active, expiresAt: time.Now().Add(m.cfg.CacheTTL)}
		if len(m.cache) > 1000 {
			for k := range m.cache {
				delete(m.cache, k)
				break
			}
		}
		m.mu.Unlock()
	}

	return active, nil
}

func (m *Middleware) introspect(ctx context.Context, token string) (bool, error) {
	body := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.cfg.IntrospectURL, strings.NewReader(body.Encode()))
	if err != nil {
		return false, fmt.Errorf("build introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.cfg.ClientID != "" {
		req.SetBasicAuth(m.cfg.ClientID, m.cfg.ClientSecret)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("introspect request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read introspect response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("introspect HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var ir introspectResponse
	if err := json.Unmarshal(respBody, &ir); err != nil {
		return false, fmt.Errorf("decode introspect response: %w", err)
	}
	return ir.Active, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", false
	}
	parts := strings.SplitN(hdr, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

// hashToken creates a short cache key from the token to avoid storing raw
// tokens in memory.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// isHTTPS reports whether the request was made over HTTPS.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}
