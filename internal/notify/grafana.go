package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/store"
)

// grafanaAnnotation is the payload for Grafana's POST /api/annotations endpoint.
type grafanaAnnotation struct {
	Text         string   `json:"text"`
	DashboardUID string   `json:"dashboardUID,omitempty"`
	Tags         []string `json:"tags"`
	Time         int64    `json:"time"`
}

func (n *Notifier) sendGrafana(wh *config.WebhookConfig, findings []store.CertFinding) {
	ann := grafanaAnnotation{
		Time: time.Now().UnixMilli(),
		Tags: grafanaTags(findings),
		Text: grafanaText(findings),
	}
	if wh.DashboardUID != "" {
		ann.DashboardUID = wh.DashboardUID
	}

	body, err := json.Marshal(ann)
	if err != nil {
		slog.Warn("notification: grafana marshal error", "err", err)
		return
	}

	url := strings.TrimRight(wh.URL, "/") + "/api/annotations"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body)) //nolint:noctx // fire-and-forget notification
	if err != nil {
		slog.Warn("notification: grafana request error", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if wh.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+wh.APIKey)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		slog.Warn("notification: grafana delivery failed", "url", url, "err", err)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close
	if resp.StatusCode >= 300 {
		slog.Warn("notification: grafana returned non-2xx", "url", url, "status", resp.StatusCode)
	}
}

func grafanaTags(findings []store.CertFinding) []string {
	tags := []string{"trustwatch"}
	var hasCrit, hasWarn bool
	for i := range findings {
		switch findings[i].Severity {
		case store.SeverityCritical:
			hasCrit = true
		case store.SeverityWarn:
			hasWarn = true
		}
	}
	if hasCrit {
		tags = append(tags, string(store.SeverityCritical))
	}
	if hasWarn {
		tags = append(tags, string(store.SeverityWarn))
	}
	return tags
}

func grafanaText(findings []store.CertFinding) string {
	summary := buildSummary(findings)
	var lines []string
	lines = append(lines, fmt.Sprintf("trustwatch: %s", summary))
	for i := range findings {
		f := &findings[i]
		lines = append(lines, fmt.Sprintf("- [%s] %s/%s (%s)",
			strings.ToUpper(string(f.Severity)), f.Namespace, f.Name, f.Source))
	}
	return strings.Join(lines, "\n")
}
