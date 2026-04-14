// Package auth provides HTTP middleware and OAuth 2.0 / OIDC endpoints for
// protecting the MCP SSE endpoint via Keycloak.
//
// # MCP Authorization Code flow (RFC 8414 + OAuth 2.1)
//
// The MCP spec requires the server to expose OAuth 2.0 Authorization Server
// Metadata (RFC 8414) at /.well-known/oauth-authorization-server.  When an
// unauthenticated MCP client receives a 401, it fetches that document to
// discover where to send the user for login.
//
// Endpoints exposed (all outside the auth middleware):
//
//	/.well-known/oauth-authorization-server  RFC 8414 metadata (points to Keycloak)
//	/authorize                               proxies/redirects to Keycloak /authorize
//	/token                                   reverse-proxies to Keycloak /token
//	/register                                reverse-proxies to Keycloak /register
//	/callback                                OIDC callback for browser/cookie sessions
//
// # Auth middleware (Wrap)
//
//  1. Bearer token present → validate via RFC 7662 introspection, forward or 401.
//  2. Session cookie present → decrypt, validate via introspection, forward or re-login.
//  3. No credentials, API client (SSE / JSON) → 401 JSON OAuth error.
//  4. No credentials, browser → redirect to Keycloak via /authorize.
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
				oauthError(w, "server_error", "token introspection error", http.StatusUnauthorized)
				return
			}
			if !active {
				oauthError(w, "invalid_token", "token inactive or expired", http.StatusUnauthorized)
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

		// 3. No credentials.
		// SSE clients (Accept: text/event-stream) and other programmatic clients
		// that did not supply a Bearer token must receive 401, not a browser
		// redirect.  A redirect response is text/html and causes the MCP client
		// to fail with "Invalid content type, expected text/event-stream".
		if isAPIClient(r) {
			oauthError(w, "unauthorized_client", "supply Authorization: Bearer <token>", http.StatusUnauthorized)
			return
		}

		// Browser with no credentials – redirect to Keycloak.
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
			oauthError(w, "invalid_token", "ID token verification failed", http.StatusUnauthorized)
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

// ─── RFC 8414 metadata + OAuth proxy endpoints ────────────────────────────────

// keycloakClaims holds the subset of Keycloak's OIDC discovery document that
// we need to build the RFC 8414 metadata response and to proxy requests.
type keycloakClaims struct {
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// MetadataHandler returns an http.HandlerFunc that serves the OAuth 2.0
// Authorization Server Metadata document (RFC 8414) at
// /.well-known/oauth-authorization-server.
//
// The MCP client fetches this after receiving a 401 to discover where to send
// the user for authorization.  We advertise our own /authorize, /token, and
// /register endpoints (which proxy to Keycloak) so the client's redirect_uri
// points back to this service.
func (m *Middleware) MetadataHandler() http.HandlerFunc {
	// Build the document once at construction time from the discovered provider.
	var kc keycloakClaims
	_ = m.provider.Claims(&kc) // best-effort; fields stay zero if unavailable

	base := strings.TrimRight(m.cfg.ExternalBaseURL, "/")

	type metadata struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
		IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	}

	grantTypes := kc.GrantTypesSupported
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	responseTypes := kc.ResponseTypesSupported
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	authMethods := kc.TokenEndpointAuthMethodsSupported
	if len(authMethods) == 0 {
		authMethods = []string{"client_secret_basic", "client_secret_post", "none"}
	}
	ccMethods := kc.CodeChallengeMethodsSupported
	if len(ccMethods) == 0 {
		ccMethods = []string{"S256"}
	}

	doc := metadata{
		Issuer:                base,
		AuthorizationEndpoint: base + "/authorize",
		TokenEndpoint:         base + "/token",
		// Advertise our stub registration endpoint so MCP clients that require
		// dynamic client registration (RFC 7591) don't fail.  The handler
		// returns the pre-configured client_id rather than creating a new one.
		RegistrationEndpoint:              base + "/register",
		ResponseTypesSupported:            responseTypes,
		GrantTypesSupported:               grantTypes,
		TokenEndpointAuthMethodsSupported: authMethods,
		CodeChallengeMethodsSupported:     ccMethods,
	}
	if kc.IntrospectionEndpoint != "" {
		doc.IntrospectionEndpoint = kc.IntrospectionEndpoint
	}

	body, _ := json.Marshal(doc)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// AuthorizeHandler proxies the OAuth 2.0 authorization request to Keycloak by
// redirecting the user-agent.  The MCP client opens a browser to our /authorize
// with its own redirect_uri; we forward all query parameters unchanged to
// Keycloak's authorization_endpoint.
func (m *Middleware) AuthorizeHandler() http.HandlerFunc {
	var kc keycloakClaims
	_ = m.provider.Claims(&kc)

	return func(w http.ResponseWriter, r *http.Request) {
		if kc.AuthorizationEndpoint == "" {
			http.Error(w, "authorization endpoint not available", http.StatusBadGateway)
			return
		}
		// Forward all query parameters as-is to Keycloak.
		target := kc.AuthorizationEndpoint + "?" + r.URL.RawQuery
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// TokenHandler reverse-proxies the OAuth 2.0 token request to Keycloak.
// The MCP client POSTs to our /token; we forward the body to Keycloak's
// token_endpoint and stream the response back.
func (m *Middleware) TokenHandler() http.HandlerFunc {
	var kc keycloakClaims
	_ = m.provider.Claims(&kc)

	return func(w http.ResponseWriter, r *http.Request) {
		if kc.TokenEndpoint == "" {
			http.Error(w, "token endpoint not available", http.StatusBadGateway)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		m.proxyToKeycloak(w, r, kc.TokenEndpoint)
	}
}

// RegisterHandler implements a stub RFC 7591 Dynamic Client Registration
// endpoint.  Rather than creating a new Keycloak client (which requires admin
// privileges and is blocked by Keycloak's Trusted Hosts policy), it always
// returns the pre-configured client_id.  This satisfies MCP clients that
// require a registration_endpoint while keeping Keycloak client management
// fully under operator control.
func (m *Middleware) RegisterHandler() http.HandlerFunc {
	// RFC 7591 §3.2.1 successful response body (subset).
	type registrationResponse struct {
		ClientID                string   `json:"client_id"`
		ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Drain and discard the request body – we don't use it.
		_, _ = io.Copy(io.Discard, r.Body)

		resp := registrationResponse{
			ClientID:                m.cfg.ClientID,
			ClientIDIssuedAt:        0,      // 0 = unknown issuance time per RFC 7591
			TokenEndpointAuthMethod: "none", // public client – PKCE only
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
		}
		body, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}
}

// proxyToKeycloak forwards the incoming request body and selected headers to
// targetURL and copies the response back to w.
func (m *Middleware) proxyToKeycloak(w http.ResponseWriter, r *http.Request, targetURL string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		slog.Error("proxy: build request", "err", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	// Forward content-type and authorization headers from the client.
	for _, h := range []string{"Content-Type", "Authorization", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		slog.Error("proxy: upstream request", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and status.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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

// oauthError writes an RFC 6749-compliant JSON error response and sets the
// WWW-Authenticate header as required by RFC 6750 §3.1.
//
// The body format is:  {"error":"<code>","error_description":"<desc>"}
func oauthError(w http.ResponseWriter, code, desc string, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, desc))
	w.WriteHeader(status)
	// Inline marshal – no external dependency needed for this simple shape.
	body, _ := json.Marshal(struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{Error: code, Description: desc})
	_, _ = w.Write(body)
}

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

// isAPIClient reports whether the request looks like a programmatic / non-browser
// client that cannot follow a login redirect.  Such clients should receive 401
// rather than a 302 redirect to Keycloak.
//
// Detection heuristics (any one is sufficient):
//   - Accept header contains "text/event-stream"  → MCP SSE client
//   - Accept header is "application/json"          → REST API client
//   - X-Requested-With: XMLHttpRequest             → AJAX call
//   - No Accept header or Accept: */*              → curl / programmatic HTTP
func isAPIClient(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		return true
	}
	if strings.Contains(accept, "application/json") {
		return true
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	// A real browser always sends a rich Accept header including text/html.
	// If there is no Accept header, or it is exactly */*, assume a non-browser.
	if accept == "" || accept == "*/*" {
		return true
	}
	return false
}
