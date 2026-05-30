// Package client provides a minimal HTTP client for the Counsel API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds provider-level configuration.
type Config struct {
	URL    string
	APIKey string
}

// Client wraps the Counsel HTTP API.
type Client struct {
	url    string
	apiKey string
	http   *http.Client
}

// New creates a Client from a Config.
func New(cfg *Config) *Client {
	return &Client{
		url:    cfg.URL,
		apiKey: cfg.APIKey,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

// do executes a request and decodes the JSON response body.
// apiKey overrides the provider-level key when non-empty.
func (c *Client) do(method, path, apiKey string, body interface{}) (map[string]interface{}, int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.url+path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	key := apiKey
	if key == "" {
		key = c.apiKey
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	var result map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return result, resp.StatusCode, nil
}

// errFromResponse converts a non-success API response into an error.
func errFromResponse(op string, status int, body map[string]interface{}) error {
	msg, _ := body["error"].(string)
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", status)
	}
	return fmt.Errorf("%s: %s", op, msg)
}

// ── Company ───────────────────────────────────────────────────────────────────

// CreateCompany calls POST /v1/companies and returns the full response map
// (companyId, spiffeId, registeredAt, apiKey).
func (c *Client) CreateCompany(companyID string, metadata map[string]interface{}) (map[string]interface{}, error) {
	body := map[string]interface{}{"companyId": companyID}
	if len(metadata) > 0 {
		body["metadata"] = metadata
	}
	result, status, err := c.do("POST", "/v1/companies", "", body)
	if err != nil {
		return nil, err
	}
	if status != 201 {
		return nil, errFromResponse("create company", status, result)
	}
	return result, nil
}

// GetCompany calls GET /v1/company authenticated with apiKey.
// Returns nil when the company no longer exists (404).
func (c *Client) GetCompany(apiKey string) (map[string]interface{}, error) {
	result, status, err := c.do("GET", "/v1/company", apiKey, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if status != 200 {
		return nil, errFromResponse("get company", status, result)
	}
	return result, nil
}

// ── Agent ─────────────────────────────────────────────────────────────────────

// RegisterAgent calls POST /v1/agents/register.
func (c *Client) RegisterAgent(apiKey, agentID string, metadata map[string]interface{}) (map[string]interface{}, error) {
	body := map[string]interface{}{"agentId": agentID}
	if len(metadata) > 0 {
		body["metadata"] = metadata
	}
	result, status, err := c.do("POST", "/v1/agents/register", apiKey, body)
	if err != nil {
		return nil, err
	}
	if status != 201 {
		return nil, errFromResponse("register agent", status, result)
	}
	return result, nil
}

// GetAgent calls GET /v1/agents/:agentId.
// Returns nil when the agent does not exist (404).
func (c *Client) GetAgent(apiKey, agentID string) (map[string]interface{}, error) {
	result, status, err := c.do("GET", "/v1/agents/"+agentID, apiKey, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if status != 200 {
		return nil, errFromResponse("get agent", status, result)
	}
	return result, nil
}

// ── API key ───────────────────────────────────────────────────────────────────

// CreateAPIKey calls POST /v1/keys.
func (c *Client) CreateAPIKey(apiKey, label string) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if label != "" {
		body["label"] = label
	}
	result, status, err := c.do("POST", "/v1/keys", apiKey, body)
	if err != nil {
		return nil, err
	}
	if status != 201 {
		return nil, errFromResponse("create API key", status, result)
	}
	return result, nil
}

// GetAPIKeys calls GET /v1/keys to list all keys for the company.
// Returns nil when the authenticating key itself is gone (401/404).
func (c *Client) GetAPIKeys(apiKey string) ([]map[string]interface{}, error) {
	result, status, err := c.do("GET", "/v1/keys", apiKey, nil)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 404 {
		return nil, nil
	}
	if status != 200 {
		return nil, errFromResponse("list API keys", status, result)
	}
	raw, _ := result["keys"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// DeleteAPIKey calls DELETE /v1/keys/:key.
func (c *Client) DeleteAPIKey(authKey, keyToDelete string) error {
	result, status, err := c.do("DELETE", "/v1/keys/"+keyToDelete, authKey, nil)
	if err != nil {
		return err
	}
	if status == 404 {
		return nil // already gone
	}
	if status != 200 {
		return errFromResponse("delete API key", status, result)
	}
	return nil
}
