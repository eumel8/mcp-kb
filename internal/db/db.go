// Package db provides PostgreSQL connectivity and incident persistence
// using pgx/v5 and the pgvector extension.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgvector "github.com/pgvector/pgvector-go"
	pgvectorpgx "github.com/pgvector/pgvector-go/pgx"
)

// Connect opens a pgx connection pool and verifies connectivity.
func Connect(dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}

	// Register pgvector type support
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return pgvectorpgx.RegisterTypes(ctx, conn)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}

// Incident represents a resolved incident stored in the knowledge base.
type Incident struct {
	ID                string     `json:"id"`
	Title             string     `json:"title"`
	Description       string     `json:"description"`
	AffectedComponent string     `json:"affected_component"`
	Severity          string     `json:"severity"`
	Environment       string     `json:"environment"`
	RootCause         string     `json:"root_cause,omitempty"`
	Resolution        string     `json:"resolution"`
	RunbookURL        string     `json:"runbook_url,omitempty"`
	Tags              []string   `json:"tags"`
	CASMTicketID      string     `json:"casm_ticket_id,omitempty"`
	AlertName         string     `json:"alert_name,omitempty"`
	ReportedBy        string     `json:"reported_by,omitempty"`
	ResolvedBy        string     `json:"resolved_by,omitempty"`
	OccurredAt        *time.Time `json:"occurred_at,omitempty"`
	ResolvedAt        *time.Time `json:"resolved_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// SimilarIncident extends Incident with a cosine similarity score.
type SimilarIncident struct {
	Incident
	Similarity float64 `json:"similarity"`
}

// StoreIncident inserts (or upserts on casm_ticket_id) an incident and
// optionally its embedding vector in a single transaction.
// If emb is nil the incident is stored without an embedding row; it can be
// retrieved by kb_get_incident and found by text search but not by vector
// similarity search.
func StoreIncident(ctx context.Context, pool *pgxpool.Pool, inc Incident, emb []float32) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO incidents (
			title, description, affected_component, severity, environment,
			root_cause, resolution, runbook_url, tags, casm_ticket_id,
			alert_name, reported_by, resolved_by, occurred_at, resolved_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		)
		ON CONFLICT (casm_ticket_id) WHERE casm_ticket_id IS NOT NULL
		DO UPDATE SET
			title              = EXCLUDED.title,
			description        = EXCLUDED.description,
			affected_component = EXCLUDED.affected_component,
			severity           = EXCLUDED.severity,
			environment        = EXCLUDED.environment,
			root_cause         = EXCLUDED.root_cause,
			resolution         = EXCLUDED.resolution,
			runbook_url        = EXCLUDED.runbook_url,
			tags               = EXCLUDED.tags,
			alert_name         = EXCLUDED.alert_name,
			reported_by        = EXCLUDED.reported_by,
			resolved_by        = EXCLUDED.resolved_by,
			occurred_at        = EXCLUDED.occurred_at,
			resolved_at        = EXCLUDED.resolved_at,
			updated_at         = NOW()
		RETURNING id`,
		inc.Title, inc.Description, inc.AffectedComponent, inc.Severity,
		inc.Environment, nullStr(inc.RootCause), inc.Resolution, nullStr(inc.RunbookURL),
		inc.Tags, nullStr(inc.CASMTicketID), nullStr(inc.AlertName),
		nullStr(inc.ReportedBy), nullStr(inc.ResolvedBy),
		inc.OccurredAt, inc.ResolvedAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert incident: %w", err)
	}

	// Only store the embedding row when an embedding was generated.
	if emb != nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO incident_embeddings (incident_id, model, embedding)
			VALUES ($1, $2, $3)
			ON CONFLICT (incident_id, model)
			DO UPDATE SET embedding = EXCLUDED.embedding, created_at = NOW()`,
			id, "text-embedding-3-small", pgvector.NewVector(emb),
		)
		if err != nil {
			return "", fmt.Errorf("upsert embedding: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit tx: %w", err)
	}
	return id, nil
}

// SearchIncidents returns the top-k most similar incidents using cosine
// similarity against the provided query embedding.
func SearchIncidents(ctx context.Context, pool *pgxpool.Pool, queryEmb []float32, topK int, filters SearchFilters) ([]SimilarIncident, error) {
	if topK <= 0 {
		topK = 5
	}

	args := pgx.NamedArgs{
		"embedding": pgvector.NewVector(queryEmb),
		"top_k":     topK,
	}

	whereClause := "1=1"
	if filters.Severity != "" {
		whereClause += " AND i.severity = @severity"
		args["severity"] = filters.Severity
	}
	if filters.Environment != "" {
		whereClause += " AND i.environment = @environment"
		args["environment"] = filters.Environment
	}
	if filters.AffectedComponent != "" {
		whereClause += " AND i.affected_component ILIKE @component"
		args["component"] = "%" + filters.AffectedComponent + "%"
	}
	if len(filters.Tags) > 0 {
		whereClause += " AND i.tags && @tags"
		args["tags"] = filters.Tags
	}

	query := fmt.Sprintf(`
		SELECT
			i.id, i.title, i.description, i.affected_component, i.severity,
			i.environment, COALESCE(i.root_cause,''), i.resolution,
			COALESCE(i.runbook_url,''), i.tags,
			COALESCE(i.casm_ticket_id,''), COALESCE(i.alert_name,''),
			COALESCE(i.reported_by,''), COALESCE(i.resolved_by,''),
			i.occurred_at, i.resolved_at, i.created_at, i.updated_at,
			1 - (e.embedding <=> @embedding::vector) AS similarity
		FROM incident_embeddings e
		JOIN incidents i ON i.id = e.incident_id
		WHERE %s
		ORDER BY e.embedding <=> @embedding::vector
		LIMIT @top_k`, whereClause)

	rows, err := pool.Query(ctx, query, args)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}
	defer rows.Close()

	var results []SimilarIncident
	for rows.Next() {
		var s SimilarIncident
		if err := rows.Scan(
			&s.ID, &s.Title, &s.Description, &s.AffectedComponent, &s.Severity,
			&s.Environment, &s.RootCause, &s.Resolution, &s.RunbookURL, &s.Tags,
			&s.CASMTicketID, &s.AlertName, &s.ReportedBy, &s.ResolvedBy,
			&s.OccurredAt, &s.ResolvedAt, &s.CreatedAt, &s.UpdatedAt,
			&s.Similarity,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// GetIncident returns a single incident by ID.
func GetIncident(ctx context.Context, pool *pgxpool.Pool, id string) (*Incident, error) {
	var inc Incident
	err := pool.QueryRow(ctx, `
		SELECT id, title, description, affected_component, severity, environment,
		       COALESCE(root_cause,''), resolution, COALESCE(runbook_url,''), tags,
		       COALESCE(casm_ticket_id,''), COALESCE(alert_name,''),
		       COALESCE(reported_by,''), COALESCE(resolved_by,''),
		       occurred_at, resolved_at, created_at, updated_at
		FROM incidents WHERE id = $1`, id,
	).Scan(
		&inc.ID, &inc.Title, &inc.Description, &inc.AffectedComponent, &inc.Severity,
		&inc.Environment, &inc.RootCause, &inc.Resolution, &inc.RunbookURL, &inc.Tags,
		&inc.CASMTicketID, &inc.AlertName, &inc.ReportedBy, &inc.ResolvedBy,
		&inc.OccurredAt, &inc.ResolvedAt, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get incident %s: %w", id, err)
	}
	return &inc, nil
}

// SearchFilters holds optional pre-filter criteria for similarity search.
type SearchFilters struct {
	Severity          string
	Environment       string
	AffectedComponent string
	Tags              []string
}

// SearchIncidentsText performs a full-text ILIKE search over title, description,
// root_cause and resolution.  Used as a fallback when no embedding client is
// available.  Returns results ordered by recency (newest first).
func SearchIncidentsText(ctx context.Context, pool *pgxpool.Pool, query string, topK int, filters SearchFilters) ([]Incident, error) {
	if topK <= 0 {
		topK = 5
	}

	conditions := []string{}
	args := []any{}
	argN := 1

	if query != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(title ILIKE $%d OR description ILIKE $%d OR root_cause ILIKE $%d OR resolution ILIKE $%d)",
			argN, argN, argN, argN))
		args = append(args, "%"+query+"%")
		argN++
	}
	if filters.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argN))
		args = append(args, filters.Severity)
		argN++
	}
	if filters.Environment != "" {
		conditions = append(conditions, fmt.Sprintf("environment = $%d", argN))
		args = append(args, filters.Environment)
		argN++
	}
	if filters.AffectedComponent != "" {
		conditions = append(conditions, fmt.Sprintf("affected_component ILIKE $%d", argN))
		args = append(args, "%"+filters.AffectedComponent+"%")
		argN++
	}
	if len(filters.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argN))
		args = append(args, filters.Tags)
		argN++
	}

	where := "1=1"
	if len(conditions) > 0 {
		where = ""
		for i, c := range conditions {
			if i > 0 {
				where += " AND "
			}
			where += c
		}
	}

	sql := fmt.Sprintf(`
		SELECT id, title, description, affected_component, severity, environment,
		       COALESCE(root_cause,''), resolution, COALESCE(runbook_url,''), tags,
		       COALESCE(casm_ticket_id,''), COALESCE(alert_name,''),
		       COALESCE(reported_by,''), COALESCE(resolved_by,''),
		       occurred_at, resolved_at, created_at, updated_at
		FROM incidents
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d`, where, argN)
	args = append(args, topK)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("text search query: %w", err)
	}
	defer rows.Close()

	var results []Incident
	for rows.Next() {
		var inc Incident
		if err := rows.Scan(
			&inc.ID, &inc.Title, &inc.Description, &inc.AffectedComponent, &inc.Severity,
			&inc.Environment, &inc.RootCause, &inc.Resolution, &inc.RunbookURL, &inc.Tags,
			&inc.CASMTicketID, &inc.AlertName, &inc.ReportedBy, &inc.ResolvedBy,
			&inc.OccurredAt, &inc.ResolvedAt, &inc.CreatedAt, &inc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, inc)
	}
	return results, rows.Err()
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
