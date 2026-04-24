# mcp-kb

MCP server providing a **RAG-based incident knowledge base**.

When an LLM agent operates a new incident it first calls `kb_search_incidents`
to retrieve semantically similar historical incidents, their root causes, and
proven resolutions.  Once the incident is resolved it calls `kb_store_incident`
to persist the knowledge for future incidents.

Incidents are stored in **PostgreSQL with the pgvector extension**.  Semantic
similarity search uses cosine distance on 1536-dimensional embeddings generated
by the OpenAI Embeddings API (or any compatible endpoint).

The HTTP/SSE endpoint is protected by **Keycloak OIDC** (Authorization Code
flow with encrypted session cookies).  Unauthenticated browser clients are
automatically redirected to Keycloak for login.  Programmatic clients may
alternatively supply an `Authorization: Bearer <token>` header validated via
RFC 7662 token introspection.

---

## Architecture

```
LLM Agent / Browser
   │
   │  ① Bearer <token>  OR  ② session cookie  OR  ③ no creds → redirect to Keycloak
   ▼
┌──────────────────────────────────────────┐
│  mcp-kb (Go / SSE)                       │
│  OIDC Auth Code flow (Keycloak)          │
│    /callback  – exchanges code for token │
│    session cookie (AES-GCM encrypted)    │
│    Bearer introspection fallback         │
│  MCP tools                               │
│    kb_search_incidents                   │
│    kb_store_incident                     │
│    kb_get_incident                       │
│    kb_stats                              │
└──────────┬───────────────────────────────┘
           │  pgx / pgvector
           ▼
┌──────────────────────────┐        ┌──────────────────────┐
│  PostgreSQL + pgvector   │        │  OpenAI Embeddings   │
│  incidents               │        │  text-embedding-3-   │
│  incident_embeddings     │        │  small (or proxy)    │
└──────────────────────────┘        └──────────────────────┘
```

---

## Tools

| Tool | Description |
|---|---|
| `kb_search_incidents` | Semantic search for similar past incidents. Call this **before** investigating a new incident. |
| `kb_store_incident` | Persist a resolved incident with its embedding. Call this **after** an incident is fully resolved. |
| `kb_get_incident` | Retrieve full details of a specific incident by UUID. |
| `kb_stats` | Return aggregate KB statistics: total incident count, breakdowns by severity and environment, and oldest/newest entry timestamps. Takes no parameters. |

### kb_search_incidents

| Parameter | Required | Description |
|---|---|---|
| `query` | yes | Free-text description of current symptoms / alert / error |
| `top_k` | no | Max results to return (default: 5, max: 20) |
| `severity` | no | Filter: `Critical` \| `Major` \| `Minor` \| `Uncritical` |
| `environment` | no | Filter: `prod` \| `preprod` \| `av` \| `playground` |
| `affected_component` | no | Partial match against component name |
| `tags` | no | Comma-separated tags (e.g. `oom,crashloopbackoff`) |

### kb_store_incident

| Parameter | Required | Description |
|---|---|---|
| `title` | yes | Short incident title |
| `description` | yes | Symptom description |
| `affected_component` | yes | Cluster/service name |
| `severity` | yes | `Critical` \| `Major` \| `Minor` \| `Uncritical` |
| `resolution` | yes | What was done to fix it |
| `root_cause` | no | Identified root cause |
| `environment` | no | `prod` (default) \| `preprod` \| `av` \| `playground` |
| `tags` | no | Comma-separated tags |
| `runbook_url` | no | Link to runbook / wiki |
| `casm_ticket_id` | no | Linked CASM ticket ID |
| `alert_name` | no | Prometheus/Alertmanager alert that fired |
| `reported_by` | no | Reporter name |
| `resolved_by` | no | Resolver name |
| `occurred_at` | no | RFC3339 timestamp (default: now) |
| `resolved_at` | no | RFC3339 timestamp (default: now) |

### kb_get_incident

| Parameter | Required | Description |
|---|---|---|
| `id` | yes | Incident UUID |

### kb_stats

No parameters. Returns a JSON object with:

| Field | Description |
|---|---|
| `total` | Total number of incidents in the knowledge base |
| `by_severity` | Map of severity → count |
| `by_environment` | Map of environment → count |
| `oldest_at` | `created_at` of the oldest incident (RFC3339) |
| `newest_at` | `created_at` of the newest incident (RFC3339) |

---

## Configuration

All configuration is via environment variables:

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | no | — | Full `postgres://` DSN (overrides individual DB_* vars) |
| `DB_HOST` | no | `localhost` | PostgreSQL host |
| `DB_PORT` | no | `5432` | PostgreSQL port |
| `DB_USER` | no | `mcp-kb` | Database user |
| `DB_PASSWORD` | **yes** | — | Database password |
| `DB_NAME` | no | `mcp-kb` | Database name |
| `DB_SSLMODE` | no | `require` | SSL mode |

### Embedding

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | **yes** | — | API key for embedding model |
| `OPENAI_BASE_URL` | no | `https://api.openai.com/v1` | Base URL (override for internal proxy) |
| `EMBEDDING_MODEL` | no | `text-embedding-3-small` | Embedding model name |

### OIDC / Keycloak (inbound protection)

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_ISSUER_URL` | **yes** (if auth) | — | Keycloak realm URL (OIDC discovery endpoint base). Example: `https://keycloak.example.com/auth/realms/myrealm` |
| `OIDC_CLIENT_ID` | **yes** (if auth) | — | OIDC client ID registered in Keycloak |
| `OIDC_CLIENT_SECRET` | **yes** (if auth) | — | OIDC client secret |
| `OIDC_EXTERNAL_BASE_URL` | **yes** (if auth) | — | Publicly reachable base URL of this service. `/callback` is appended to form the `redirect_uri`. Example: `https://mcp-kb.example.com` |
| `OIDC_INTROSPECT_URL` | no | — | RFC 7662 token introspection endpoint. When set, validates every token (Bearer and cookie) against Keycloak with a 30 s cache. |
| `OIDC_COOKIE_ENCRYPTION_KEY` | no | ephemeral | Hex-encoded 32-byte AES key for session cookie encryption. Generate with `openssl rand -hex 32`. If unset, a random key is generated at startup (sessions won't survive pod restarts). |

#### Auth flow summary

```
Browser (no token)          → 302 redirect to Keycloak login
                            → Keycloak authenticates user
                            → 302 redirect to <OIDC_EXTERNAL_BASE_URL>/callback?code=…
                            → callback exchanges code, sets AES-GCM session cookie
                            → 302 redirect to original URL

Browser (valid cookie)      → token extracted from cookie, introspected (cached 30 s)
                            → request forwarded to MCP tools

API client (Bearer token)   → token introspected via OIDC_INTROSPECT_URL (cached 30 s)
                            → request forwarded to MCP tools

Unauthenticated API client  → 401 Unauthorized  (no redirect for Bearer clients)
```

Leave `OIDC_ISSUER_URL` unset to disable authentication entirely (development only).

### Transport

| Variable | Required | Default | Description |
|---|---|---|---|
| `MCP_TRANSPORT` | no | `sse` | `sse` (HTTP) or `stdio` (subprocess, no auth) |
| `MCP_PORT` | no | `8080` | Listen port for SSE mode |

---

## Database schema

The schema is in `db/schema.sql` and is automatically applied via the
`postgres-init` ConfigMap on first PostgreSQL startup.

### Key tables

```
incidents               – one row per resolved incident
incident_embeddings     – vector(1536) per incident, indexed with IVFFlat
```

The embedding is generated from:

```
Title: <title>
Description: <description>
Root Cause: <root_cause>
Resolution: <resolution>
Tags: [<tags>]
```

---

## CI/CD

The GitHub Actions workflow (`.github/workflows/release.yaml`) triggers on every
`v*` tag push.

### Jobs

| Job | Description |
|---|---|
| `build-binaries` | Cross-compiles binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 |
| `release` | Creates a GitHub release with binary assets attached |
| `build-and-push-container` | Builds a multi-arch image and pushes it to GHCR |

### Image destination

Images are published to the GitHub Container Registry (`ghcr.io`):

```
ghcr.io/<owner>/mcp-kb:<semver>
ghcr.io/<owner>/mcp-kb:<major>.<minor>
ghcr.io/<owner>/mcp-kb:<major>
ghcr.io/<owner>/mcp-kb:sha-<short-sha>
```

The workflow uses `GITHUB_TOKEN` — no additional credentials are required.

---

## Build

```sh
# Build binary
go build -o mcp-kb .

# Build Docker image
docker build -t mcp-kb .
```

---

## Running locally

```sh
# Start a local PostgreSQL with pgvector
docker run -d --name pgvector \
  -e POSTGRES_USER=mcp-kb \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=mcp-kb \
  -p 5432:5432 \
  pgvector/pgvector:pg16

# Apply schema
psql postgres://mcp-kb:secret@localhost:5432/mcp-kb -f db/schema.sql

# Run the MCP server (SSE, no auth for local dev)
export DB_HOST=localhost
export DB_USER=mcp-kb
export DB_PASSWORD=secret
export DB_SSLMODE=disable
export OPENAI_API_KEY=sk-...
export MCP_TRANSPORT=sse

./mcp-kb
# Listening on :8080
```

---

## Kubernetes deployment

### Prerequisites

- Kubernetes ≥ 1.25
- `kubectl` configured for the target cluster
- Container image pushed to your registry
- [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) controller installed
- [cert-manager](https://cert-manager.io/) installed with a `ClusterIssuer` named
  `letsencrypt-prod` (or adjust `cert-manager.io/cluster-issuer` in the manifest)
- DNS record for the service hostname pointing to the ingress controller's external IP

### Deploy

```sh
# 1. Create namespace
kubectl apply -f deploy/namespace.yaml

# 2. Deploy PostgreSQL with pgvector
kubectl apply -f deploy/postgres.yaml

# 3. Edit secrets in deploy/mcp-kb.yaml, then deploy the MCP service
#    (or use Sealed Secrets / External Secrets before applying)
kubectl apply -f deploy/mcp-kb.yaml

# 4. Apply network policies
kubectl apply -f deploy/network-policy.yaml

# 5. Apply the Ingress
#    Edit the host name in deploy/ingress.yaml first, then:
kubectl apply -f deploy/ingress.yaml

# 6. Verify
kubectl -n mcp-kb get pods
kubectl -n mcp-kb get ingress
kubectl -n mcp-kb describe certificate mcp-kb-tls   # cert-manager TLS status
kubectl -n mcp-kb logs deployment/mcp-kb
```

### Helm (values-driven)

The `values.yaml` and `values.schema.json` provide a self-documenting,
validated configuration surface.  Wire them into your Helm chart or ArgoCD
application:

```sh
# Validate values against schema
helm lint . --values values.yaml

# Render manifests
helm template mcp-kb . --values values.yaml
```

Key values to override for production:

```yaml
image:
  repository: your.registry/mcp-kb
  tag: "1.0.0"

oidc:
  issuerURL: "https://keycloak.prod.example.com/auth/realms/myrealm"
  externalBaseURL: "https://mcp-kb.prod.example.com"
  introspectURL: "https://keycloak.prod.example.com/auth/realms/myrealm/protocol/openid-connect/token/introspect"

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
  hosts:
    - host: mcp-kb.prod.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: mcp-kb-tls
      hosts:
        - mcp-kb.prod.example.com

secrets:
  existingSecret: "mcp-kb-secrets"   # managed externally
```

---

## Security

- **Browser clients** are authenticated via the Keycloak OIDC Authorization
  Code flow.  The resulting access token is stored in an AES-GCM-encrypted
  HTTP-only session cookie.
- **Programmatic/API clients** supply `Authorization: Bearer <token>`, which
  is validated via RFC 7662 introspection against Keycloak.
- Introspection results are **cached for 30 seconds** to avoid hammering
  Keycloak on every MCP tool call.
- The container runs as **non-root** (UID 65534) with a read-only filesystem
  and all Linux capabilities dropped.
- PostgreSQL is only reachable from the MCP service pod via `NetworkPolicy`.
- **Never commit plaintext secrets** – use Sealed Secrets, External Secrets
  Operator, or Vault.

---

## MCP client configuration

For programmatic / API clients that supply a Bearer token (no browser redirect):

```json
{
  "mcpServers": {
    "mcp-kb": {
      "url": "http://mcp-kb.mcp-kb.svc.cluster.local/sse",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

For stdio mode (local development without auth):

```json
{
  "mcpServers": {
    "mcp-kb": {
      "command": "/path/to/mcp-kb",
      "env": {
        "DB_HOST": "localhost",
        "DB_PASSWORD": "secret",
        "DB_SSLMODE": "disable",
        "OPENAI_API_KEY": "sk-...",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

---

## Suggested LLM system prompt addition

```
You have access to an incident knowledge base.

When a new incident is reported:
1. Call kb_search_incidents with the incident description to find similar past incidents.
2. Present the top results including their root cause and resolution to guide investigation.
3. After the incident is resolved, call kb_store_incident to record the incident,
   root cause, and resolution for future use.
```
