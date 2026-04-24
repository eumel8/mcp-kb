// Package db provides PostgreSQL connectivity and incident persistence.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens a pgx connection pool and verifies connectivity.
func Connect(dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
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

// RankedIncident extends Incident with a full-text relevance rank.
type RankedIncident struct {
	Incident
	Rank float64 `json:"rank"`
}

// SearchFilters holds optional pre-filter criteria for search.
type SearchFilters struct {
	Severity          string
	Environment       string
	AffectedComponent string
	Tags              []string
}

// StoreIncident inserts (or upserts on casm_ticket_id) an incident.
// The search_vector column is maintained automatically by a DB trigger.
func StoreIncident(ctx context.Context, pool *pgxpool.Pool, inc Incident) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
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
			resolved_at        = EXCLUDED.resolved_at
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
	return id, nil
}

// SearchIncidents performs ranked full-text search using PostgreSQL tsvector.
// When query is empty only the filter criteria are applied and results are
// ordered by recency.  Ranking uses ts_rank_cd (cover density weighting).
func SearchIncidents(ctx context.Context, pool *pgxpool.Pool, query string, topK int, filters SearchFilters) ([]RankedIncident, error) {
	if topK <= 0 {
		topK = 5
	}

	conditions := []string{}
	args := []any{}
	argN := 1

	// Full-text condition using plainto_tsquery so users don't need tsquery syntax.
	if query != "" {
		conditions = append(conditions, fmt.Sprintf(
			"search_vector @@ plainto_tsquery('english', $%d)", argN))
		args = append(args, query)
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

	// Rank by ts_rank_cd when a text query is given; otherwise order by recency.
	var rankExpr, orderExpr string
	if query != "" {
		rankExpr = fmt.Sprintf(
			", ts_rank_cd(search_vector, plainto_tsquery('english', $%d)) AS rank", argN)
		orderExpr = "ORDER BY rank DESC"
		args = append(args, query)
		argN++
	} else {
		rankExpr = ", 0.0 AS rank"
		orderExpr = "ORDER BY created_at DESC"
	}

	sql := fmt.Sprintf(`
		SELECT id, title, description, affected_component, severity, environment,
		       COALESCE(root_cause,''), resolution, COALESCE(runbook_url,''), tags,
		       COALESCE(casm_ticket_id,''), COALESCE(alert_name,''),
		       COALESCE(reported_by,''), COALESCE(resolved_by,''),
		       occurred_at, resolved_at, created_at, updated_at
		       %s
		FROM incidents
		WHERE %s
		%s
		LIMIT $%d`, rankExpr, where, orderExpr, argN)
	args = append(args, topK)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}
	defer rows.Close()

	var results []RankedIncident
	for rows.Next() {
		var r RankedIncident
		if err := rows.Scan(
			&r.ID, &r.Title, &r.Description, &r.AffectedComponent, &r.Severity,
			&r.Environment, &r.RootCause, &r.Resolution, &r.RunbookURL, &r.Tags,
			&r.CASMTicketID, &r.AlertName, &r.ReportedBy, &r.ResolvedBy,
			&r.OccurredAt, &r.ResolvedAt, &r.CreatedAt, &r.UpdatedAt,
			&r.Rank,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// Stats aggregates knowledge-base statistics: total incident count plus
// breakdowns by severity and environment, and newest/oldest created timestamps.
type Stats struct {
	Total         int            `json:"total"`
	BySeverity    map[string]int `json:"by_severity"`
	ByEnvironment map[string]int `json:"by_environment"`
	OldestAt      *time.Time     `json:"oldest_at,omitempty"`
	NewestAt      *time.Time     `json:"newest_at,omitempty"`
}

// GetStats returns aggregate counts over the incidents table.
func GetStats(ctx context.Context, pool *pgxpool.Pool) (*Stats, error) {
	s := &Stats{
		BySeverity:    map[string]int{},
		ByEnvironment: map[string]int{},
	}

	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM incidents`,
	).Scan(&s.Total, &s.OldestAt, &s.NewestAt); err != nil {
		return nil, fmt.Errorf("count incidents: %w", err)
	}

	sevRows, err := pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM incidents GROUP BY severity ORDER BY severity`)
	if err != nil {
		return nil, fmt.Errorf("group by severity: %w", err)
	}
	for sevRows.Next() {
		var sev string
		var n int
		if err := sevRows.Scan(&sev, &n); err != nil {
			sevRows.Close()
			return nil, fmt.Errorf("scan severity: %w", err)
		}
		s.BySeverity[sev] = n
	}
	sevRows.Close()
	if err := sevRows.Err(); err != nil {
		return nil, err
	}

	envRows, err := pool.Query(ctx, `
		SELECT environment, COUNT(*) FROM incidents GROUP BY environment ORDER BY environment`)
	if err != nil {
		return nil, fmt.Errorf("group by environment: %w", err)
	}
	for envRows.Next() {
		var env string
		var n int
		if err := envRows.Scan(&env, &n); err != nil {
			envRows.Close()
			return nil, fmt.Errorf("scan environment: %w", err)
		}
		s.ByEnvironment[env] = n
	}
	envRows.Close()
	if err := envRows.Err(); err != nil {
		return nil, err
	}

	return s, nil
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

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
