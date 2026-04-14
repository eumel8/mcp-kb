// Package embedding provides an OpenAI-compatible client for generating
// text embeddings used by the RAG knowledge base.
package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client generates embeddings via the OpenAI Embeddings API.
type Client struct {
	apiKey  string
	baseURL string
	model   string
	http    *http.Client
}

// NewOpenAIClient creates an embedding client targeting the given base URL
// (default: https://api.openai.com/v1).
func NewOpenAIClient(apiKey, baseURL, model string) *Client {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if model == "" {
		model = "text-embedding-3-small"
	}
	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		model:   model,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// Embed generates an embedding vector for the given text.
// The returned slice length matches the model's output dimension
// (1536 for text-embedding-3-small).
func (c *Client) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody, err := json.Marshal(map[string]any{
		"model": c.model,
		"input": text,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/embeddings", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(result.Data) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}
	return result.Data[0].Embedding, nil
}

// BuildIncidentText creates the text blob that is embedded for an incident.
// Consistent formatting ensures retrieval quality.
func BuildIncidentText(title, description, rootCause, resolution string, tags []string) string {
	return fmt.Sprintf("Title: %s\nDescription: %s\nRoot Cause: %s\nResolution: %s\nTags: %v",
		title, description, rootCause, resolution, tags)
}
