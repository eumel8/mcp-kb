// Package tools registers all MCP tools for the incident knowledge base.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eumel8/mcp-kb/internal/db"
	"github.com/eumel8/mcp-kb/internal/embedding"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Register adds all knowledge-base tools to the MCP server.
func Register(s *server.MCPServer, pool *pgxpool.Pool, embedClient *embedding.Client) {
	registerSearchIncidents(s, pool, embedClient)
	registerStoreIncident(s, pool, embedClient)
	registerGetIncident(s, pool)
}

// ── kb_search_incidents ───────────────────────────────────────────────────────

func registerSearchIncidents(s *server.MCPServer, pool *pgxpool.Pool, embedClient *embedding.Client) {
	tool := mcp.NewTool("kb_search_incidents",
		mcp.WithDescription(
			"Search the incident knowledge base for similar past incidents using semantic (vector) similarity. "+
				"Call this tool at the start of incident response to retrieve relevant historical context, "+
				"known root causes, and proven resolutions before investigating a new incident."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Free-text description of the current incident symptoms, alert name, or error message. "+
				"The more detail you provide, the better the results.")),
		mcp.WithNumber("top_k",
			mcp.Description("Maximum number of similar incidents to return (default: 5, max: 20).")),
		mcp.WithString("severity",
			mcp.Description("Optional filter: Critical | Major | Minor | Uncritical")),
		mcp.WithString("environment",
			mcp.Description("Optional filter: prod | preprod | av | playground")),
		mcp.WithString("affected_component",
			mcp.Description("Optional filter: partial match against component name (e.g. 'ingress-nginx', 'ship-lab-1').")),
		mcp.WithString("tags",
			mcp.Description("Optional comma-separated tags to filter by (e.g. 'oom,crashloopbackoff').")),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query := mcp.ParseString(req, "query", "")
		if query == "" {
			return mcp.NewToolResultError("query is required"), nil
		}

		topK := int(mcp.ParseFloat64(req, "top_k", 5))
		if topK > 20 {
			topK = 20
		}

		filters := db.SearchFilters{
			Severity:          mcp.ParseString(req, "severity", ""),
			Environment:       mcp.ParseString(req, "environment", ""),
			AffectedComponent: mcp.ParseString(req, "affected_component", ""),
		}
		if tagStr := mcp.ParseString(req, "tags", ""); tagStr != "" {
			for _, t := range strings.Split(tagStr, ",") {
				filters.Tags = append(filters.Tags, strings.TrimSpace(t))
			}
		}

		emb, err := embedClient.Embed(ctx, query)
		if err != nil {
			return mcp.NewToolResultError("generate query embedding: " + err.Error()), nil
		}

		results, err := db.SearchIncidents(ctx, pool, emb, topK, filters)
		if err != nil {
			return mcp.NewToolResultError("search incidents: " + err.Error()), nil
		}

		if len(results) == 0 {
			return mcp.NewToolResultText("No similar incidents found in the knowledge base."), nil
		}

		return jsonResult(results)
	})
}

// ── kb_store_incident ─────────────────────────────────────────────────────────

func registerStoreIncident(s *server.MCPServer, pool *pgxpool.Pool, embedClient *embedding.Client) {
	tool := mcp.NewTool("kb_store_incident",
		mcp.WithDescription(
			"Store a resolved incident in the knowledge base so it can be found by future semantic searches. "+
				"Call this tool after an incident has been fully resolved and root cause identified."),
		mcp.WithString("title",
			mcp.Required(),
			mcp.Description("Short descriptive title of the incident (e.g. 'OOMKilled pods on ship-lab-1 worker nodes').")),
		mcp.WithString("description",
			mcp.Required(),
			mcp.Description("Detailed description of the symptoms and what was observed.")),
		mcp.WithString("affected_component",
			mcp.Required(),
			mcp.Description("Name of the affected cluster, service, or component (e.g. 'cluster/ship-lab-1', 'ingress-nginx').")),
		mcp.WithString("severity",
			mcp.Required(),
			mcp.Description("Incident severity: Critical | Major | Minor | Uncritical")),
		mcp.WithString("resolution",
			mcp.Required(),
			mcp.Description("What was done to resolve the incident.")),
		mcp.WithString("root_cause",
			mcp.Description("Identified root cause of the incident.")),
		mcp.WithString("environment",
			mcp.Description("Environment: prod | preprod | av | playground (default: prod).")),
		mcp.WithString("tags",
			mcp.Description("Comma-separated tags for categorisation (e.g. 'oom,memory,node').")),
		mcp.WithString("runbook_url",
			mcp.Description("URL to the runbook or wiki page for this type of incident.")),
		mcp.WithString("casm_ticket_id",
			mcp.Description("CASM trouble ticket ID linked to this incident.")),
		mcp.WithString("alert_name",
			mcp.Description("Prometheus/Alertmanager alert name that fired.")),
		mcp.WithString("reported_by",
			mcp.Description("Person or system that reported the incident.")),
		mcp.WithString("resolved_by",
			mcp.Description("Person or team that resolved the incident.")),
		mcp.WithString("occurred_at",
			mcp.Description("RFC3339 timestamp when the incident occurred (default: now).")),
		mcp.WithString("resolved_at",
			mcp.Description("RFC3339 timestamp when the incident was resolved (default: now).")),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		title := mcp.ParseString(req, "title", "")
		description := mcp.ParseString(req, "description", "")
		component := mcp.ParseString(req, "affected_component", "")
		severity := mcp.ParseString(req, "severity", "")
		resolution := mcp.ParseString(req, "resolution", "")

		if title == "" || description == "" || component == "" || severity == "" || resolution == "" {
			return mcp.NewToolResultError("title, description, affected_component, severity, and resolution are required"), nil
		}

		// Validate severity
		switch severity {
		case "Critical", "Major", "Minor", "Uncritical":
		default:
			return mcp.NewToolResultError("severity must be one of: Critical, Major, Minor, Uncritical"), nil
		}

		inc := db.Incident{
			Title:             title,
			Description:       description,
			AffectedComponent: component,
			Severity:          severity,
			Resolution:        resolution,
			RootCause:         mcp.ParseString(req, "root_cause", ""),
			Environment:       getEnvOrDefault(mcp.ParseString(req, "environment", ""), "prod"),
			RunbookURL:        mcp.ParseString(req, "runbook_url", ""),
			CASMTicketID:      mcp.ParseString(req, "casm_ticket_id", ""),
			AlertName:         mcp.ParseString(req, "alert_name", ""),
			ReportedBy:        mcp.ParseString(req, "reported_by", ""),
			ResolvedBy:        mcp.ParseString(req, "resolved_by", ""),
		}

		// Tags
		if tagStr := mcp.ParseString(req, "tags", ""); tagStr != "" {
			for _, t := range strings.Split(tagStr, ",") {
				inc.Tags = append(inc.Tags, strings.TrimSpace(t))
			}
		}

		// Timestamps
		now := time.Now().UTC()
		if ts := mcp.ParseString(req, "occurred_at", ""); ts != "" {
			t, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				return mcp.NewToolResultError("occurred_at must be RFC3339: " + err.Error()), nil
			}
			inc.OccurredAt = &t
		} else {
			inc.OccurredAt = &now
		}

		if ts := mcp.ParseString(req, "resolved_at", ""); ts != "" {
			t, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				return mcp.NewToolResultError("resolved_at must be RFC3339: " + err.Error()), nil
			}
			inc.ResolvedAt = &t
		} else {
			inc.ResolvedAt = &now
		}

		// Generate embedding from combined incident text
		embText := embedding.BuildIncidentText(
			inc.Title, inc.Description, inc.RootCause, inc.Resolution, inc.Tags)
		emb, err := embedClient.Embed(ctx, embText)
		if err != nil {
			return mcp.NewToolResultError("generate embedding: " + err.Error()), nil
		}

		id, err := db.StoreIncident(ctx, pool, inc, emb)
		if err != nil {
			return mcp.NewToolResultError("store incident: " + err.Error()), nil
		}

		return jsonResult(map[string]string{
			"id":      id,
			"message": fmt.Sprintf("Incident stored successfully with ID %s", id),
		})
	})
}

// ── kb_get_incident ───────────────────────────────────────────────────────────

func registerGetIncident(s *server.MCPServer, pool *pgxpool.Pool) {
	tool := mcp.NewTool("kb_get_incident",
		mcp.WithDescription("Retrieve full details of a specific incident from the knowledge base by its UUID."),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("UUID of the incident as returned by kb_store_incident or kb_search_incidents.")),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := mcp.ParseString(req, "id", "")
		if id == "" {
			return mcp.NewToolResultError("id is required"), nil
		}

		inc, err := db.GetIncident(ctx, pool, id)
		if err != nil {
			return mcp.NewToolResultError("get incident: " + err.Error()), nil
		}
		return jsonResult(inc)
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

func getEnvOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
