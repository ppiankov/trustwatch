// Package ct provides Certificate Transparency log monitoring via crt.sh.
package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultBaseURL   = "https://crt.sh"
	defaultTimeout   = 30 * time.Second
	maxResponseBytes = 10 << 20 // 10 MB
)

// Entry represents a certificate record from crt.sh.
type Entry struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	IssuerName   string `json:"issuer_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	ID           int64  `json:"id"`
}

// Client queries crt.sh for CT log entries.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a CT log client. Options can override baseURL for testing.
func NewClient(opts ...func(*Client)) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		baseURL:    defaultBaseURL,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// WithBaseURL overrides the crt.sh base URL (for testing).
func WithBaseURL(u string) func(*Client) {
	return func(c *Client) {
		c.baseURL = u
	}
}

// FetchCerts queries crt.sh for certificates matching the given domain.
// Returns deduplicated entries by serial number.
func (c *Client) FetchCerts(ctx context.Context, domain string) ([]Entry, error) {
	u := fmt.Sprintf("%s/?q=%s&output=json&exclude=expired",
		c.baseURL, url.QueryEscape("%."+domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building CT request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying CT logs: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT log query returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading CT response: %w", err)
	}

	var entries []Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing CT response: %w", err)
	}

	return dedup(entries), nil
}

// dedup removes duplicate entries by serial number, keeping the first occurrence.
func dedup(entries []Entry) []Entry {
	seen := make(map[string]bool, len(entries))
	result := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if seen[e.SerialNumber] {
			continue
		}
		seen[e.SerialNumber] = true
		result = append(result, e)
	}
	return result
}
