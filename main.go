// Command mcp-kb is an MCP (Model Context Protocol) server that
// provides a RAG-based incident knowledge base.
//
// # Overview
//
// When a new incident is being operated, the LLM calls kb_search_incidents to
// retrieve semantically similar past incidents from the PostgreSQL/pgvector
// store.  Once an incident is resolved, the LLM calls kb_store_incident to
// persist the incident together with its embedding so future searches can find
// it.
//
// # Embedding
//
// The server calls the OpenAI Embeddings API (text-embedding-3-small by
// default) to convert free-text incident data into vectors.  Any
// OpenAI-compatible endpoint is accepted via OPENAI_BASE_URL.
//
// # Authentication (inbound)
//
// The HTTP/SSE endpoint is protected via Keycloak (or any OIDC-compatible
// provider) using the Authorization Code flow with encrypted session cookies.
// Unauthenticated browser clients are automatically redirected to Keycloak.
// Programmatic clients may alternatively supply an Authorization: Bearer
// <token> header, which is validated via RFC 7662 token introspection.
//
// Required variables: OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
// OIDC_EXTERNAL_BASE_URL.
// Optional: OIDC_INTROSPECT_URL (enables introspection for both bearer and
// cookie sessions), OIDC_COOKIE_ENCRYPTION_KEY (32-byte hex; ephemeral if
// unset).
//
// # Database
//
// Expects a PostgreSQL database with the pgvector extension and the schema
// from db/schema.sql applied.  Configure via DATABASE_URL or the individual
// DB_* variables.
//
// # Transport
//
// Set MCP_TRANSPORT=sse (default) to serve HTTP+SSE.
// Set MCP_TRANSPORT=stdio for subprocess / pipe mode (no auth middleware).
// MCP_PORT controls the listen port (default 8080).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/eumel8/mcp-kb/internal/auth"
	"github.com/eumel8/mcp-kb/internal/db"
	"github.com/eumel8/mcp-kb/internal/embedding"
	"github.com/eumel8/mcp-kb/internal/tools"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := configFromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	// Database pool
	pool, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	// Embedding client – optional; nil when OPENAI_API_KEY is not set.
	var embedClient *embedding.Client
	if cfg.OpenAIAPIKey != "" {
		embedClient = embedding.NewOpenAIClient(cfg.OpenAIAPIKey, cfg.OpenAIBaseURL, cfg.EmbeddingModel)
	}

	// MCP server
	s := server.NewMCPServer(
		"mcp-kb",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	tools.Register(s, pool, embedClient)

	transport := cfg.Transport
	switch transport {
	case "stdio":
		slog.Info("starting stdio server")
		return server.ServeStdio(s)
	default: // sse + streamable HTTP
		port := cfg.Port
		addr := ":" + port

		// Legacy SSE transport (MCP 2024) – kept for backward compatibility.
		sseServer := server.NewSSEServer(s, server.WithBaseURL("http://localhost:"+port))

		// Streamable HTTP transport (MCP 2025) – OpenCode and other modern
		// clients use this; it POSTs to /mcp by default.
		streamServer := server.NewStreamableHTTPServer(s)

		mux := http.NewServeMux()

		// /healthz is intentionally outside the auth middleware so that the
		// Kubernetes liveness and readiness probes always get a 200 OK without
		// needing credentials.
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})

		if cfg.OIDCIssuerURL != "" {
			authMiddleware, err := auth.NewMiddleware(context.Background(), auth.Config{
				IssuerURL:           cfg.OIDCIssuerURL,
				ClientID:            cfg.OIDCClientID,
				ClientSecret:        cfg.OIDCClientSecret,
				ExternalBaseURL:     cfg.OIDCExternalBaseURL,
				CookieEncryptionKey: cfg.OIDCCookieEncryptionKey,
				IntrospectURL:       cfg.OIDCIntrospectURL,
			})
			if err != nil {
				return fmt.Errorf("create auth middleware: %w", err)
			}

			// OAuth 2.0 / OIDC endpoints – all outside the auth middleware so
			// unauthenticated MCP clients can discover and use them.
			mux.Handle("/.well-known/oauth-authorization-server", authMiddleware.MetadataHandler())
			mux.Handle("/authorize", authMiddleware.AuthorizeHandler())
			mux.Handle("/token", authMiddleware.TokenHandler())
			mux.Handle("/register", authMiddleware.RegisterHandler())
			mux.Handle("/callback", authMiddleware.CallbackHandler())

			// Both transports behind the auth middleware.
			mux.Handle("/mcp", authMiddleware.Wrap(streamServer))
			mux.Handle("/sse", authMiddleware.Wrap(sseServer))
			mux.Handle("/message", authMiddleware.Wrap(sseServer))
			// Catch-all for any other paths (also auth-protected).
			mux.Handle("/", authMiddleware.Wrap(sseServer))

			slog.Info("OIDC authentication enabled",
				"issuer", cfg.OIDCIssuerURL,
				"external_base_url", cfg.OIDCExternalBaseURL,
			)
		} else {
			mux.Handle("/mcp", streamServer)
			mux.Handle("/", sseServer)
			slog.Warn("OIDC not configured – endpoint is unauthenticated")
		}

		slog.Info("starting SSE+Streamable HTTP server", "addr", addr)
		return http.ListenAndServe(addr, mux)
	}
}

// serverConfig holds all runtime configuration.
type serverConfig struct {
	DatabaseURL string
	Transport   string
	Port        string

	OpenAIAPIKey   string
	OpenAIBaseURL  string
	EmbeddingModel string

	// OIDC / Keycloak
	OIDCIssuerURL           string
	OIDCClientID            string
	OIDCClientSecret        string
	OIDCExternalBaseURL     string
	OIDCIntrospectURL       string
	OIDCCookieEncryptionKey []byte
}

func configFromEnv() (serverConfig, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Build from individual vars
		host := getEnvOrDefault("DB_HOST", "localhost")
		port := getEnvOrDefault("DB_PORT", "5432")
		user := getEnvOrDefault("DB_USER", "mcp-kb")
		pass := os.Getenv("DB_PASSWORD")
		name := getEnvOrDefault("DB_NAME", "mcp-kb")
		sslmode := getEnvOrDefault("DB_SSLMODE", "require")
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, name, sslmode)
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		slog.Warn("OPENAI_API_KEY not set – embedding features (kb_search_incidents, kb_store_incident) will be unavailable")
	}

	var cookieKey []byte
	if hexKey := os.Getenv("OIDC_COOKIE_ENCRYPTION_KEY"); hexKey != "" {
		var err error
		cookieKey, err = hex.DecodeString(hexKey)
		if err != nil {
			return serverConfig{}, fmt.Errorf("OIDC_COOKIE_ENCRYPTION_KEY must be a hex-encoded string: %w", err)
		}
		if n := len(cookieKey); n != 16 && n != 24 && n != 32 {
			return serverConfig{}, fmt.Errorf("OIDC_COOKIE_ENCRYPTION_KEY must be 16, 24, or 32 bytes (got %d)", n)
		}
	}

	return serverConfig{
		DatabaseURL: dbURL,
		Transport:   getEnvOrDefault("MCP_TRANSPORT", "sse"),
		Port:        getEnvOrDefault("MCP_PORT", "8080"),

		OpenAIAPIKey:   apiKey,
		OpenAIBaseURL:  getEnvOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"),
		EmbeddingModel: getEnvOrDefault("EMBEDDING_MODEL", "text-embedding-3-small"),

		OIDCIssuerURL:           os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:            os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:        os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCExternalBaseURL:     os.Getenv("OIDC_EXTERNAL_BASE_URL"),
		OIDCIntrospectURL:       os.Getenv("OIDC_INTROSPECT_URL"),
		OIDCCookieEncryptionKey: cookieKey,
	}, nil
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
