// Package notify sends webhook notifications when findings cross severity thresholds.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/store"
)

const httpTimeout = 10 * time.Second

// Notifier sends alerts for findings that cross severity thresholds.
type Notifier struct {
	severities map[store.Severity]bool
	sent       map[string]time.Time
	client     *http.Client
	webhooks   []config.WebhookConfig
	cooldown   time.Duration
	mu         sync.Mutex
}

// New creates a Notifier from notification config. Returns nil if not enabled or no webhooks.
func New(cfg config.NotificationConfig) *Notifier {
	if !cfg.Enabled || len(cfg.Webhooks) == 0 {
		return nil
	}

	sevs := make(map[store.Severity]bool)
	for _, s := range cfg.Severities {
		sevs[store.Severity(s)] = true
	}
	// Default to critical+warn if none specified
	if len(sevs) == 0 {
		sevs[store.SeverityCritical] = true
		sevs[store.SeverityWarn] = true
	}

	cooldown := cfg.Cooldown
	if cooldown == 0 {
		cooldown = time.Hour
	}

	return &Notifier{
		webhooks:   cfg.Webhooks,
		severities: sevs,
		cooldown:   cooldown,
		sent:       make(map[string]time.Time),
		client:     &http.Client{Timeout: httpTimeout},
	}
}

// findingKey returns a deduplication key for a finding.
func findingKey(f *store.CertFinding) string {
	return fmt.Sprintf("%s/%s/%s", f.Source, f.Namespace, f.Name)
}

// Notify compares prev and curr snapshots and sends notifications for new or escalated findings.
func (n *Notifier) Notify(prev, curr store.Snapshot) {
	prevMap := make(map[string]store.Severity)
	for i := range prev.Findings {
		prevMap[findingKey(&prev.Findings[i])] = prev.Findings[i].Severity
	}

	now := time.Now()
	var newFindings []store.CertFinding

	n.mu.Lock()
	for i := range curr.Findings {
		f := &curr.Findings[i]
		if !n.severities[f.Severity] {
			continue
		}

		key := findingKey(f)
		prevSev, existed := prevMap[key]

		// Skip if existed at same or higher severity
		if existed && !isEscalation(prevSev, f.Severity) {
			continue
		}

		// Check cooldown
		if lastSent, ok := n.sent[key]; ok && now.Sub(lastSent) < n.cooldown {
			continue
		}

		newFindings = append(newFindings, *f)
		n.sent[key] = now
	}
	n.mu.Unlock()

	resolvedKeys := n.computeResolved(prev, curr)

	if len(newFindings) == 0 && len(resolvedKeys) == 0 {
		return
	}

	n.dispatch(newFindings, resolvedKeys)
}

// computeResolved returns dedup keys for findings in prev (matching severity) absent from curr.
func (n *Notifier) computeResolved(prev, curr store.Snapshot) []string {
	currKeys := make(map[string]bool, len(curr.Findings))
	for i := range curr.Findings {
		currKeys[findingKey(&curr.Findings[i])] = true
	}
	var resolved []string
	for i := range prev.Findings {
		f := &prev.Findings[i]
		if !n.severities[f.Severity] {
			continue
		}
		if key := findingKey(f); !currKeys[key] {
			resolved = append(resolved, key)
		}
	}
	return resolved
}

// dispatch sends new findings and resolve events to all configured webhooks.
func (n *Notifier) dispatch(newFindings []store.CertFinding, resolvedKeys []string) {
	for _, wh := range n.webhooks {
		if len(newFindings) > 0 {
			switch wh.Type {
			case "slack":
				n.sendSlack(wh.URL, newFindings)
			case "pagerduty":
				n.sendPagerDuty(wh, newFindings)
			default:
				n.sendGeneric(wh.URL, newFindings)
			}
		}
		if wh.Type == "pagerduty" && len(resolvedKeys) > 0 {
			n.resolvePagerDuty(wh, resolvedKeys)
		}
	}
}

// isEscalation returns true if the severity went from warn to critical.
func isEscalation(prev, curr store.Severity) bool {
	return prev == store.SeverityWarn && curr == store.SeverityCritical
}

// GenericPayload is the JSON body sent to generic webhooks.
type GenericPayload struct {
	Timestamp time.Time        `json:"timestamp"`
	Summary   string           `json:"summary"`
	Findings  []GenericFinding `json:"findings"`
}

// GenericFinding is a single finding in the generic webhook payload.
type GenericFinding struct {
	NotAfter  time.Time        `json:"notAfter"`
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	Source    store.SourceKind `json:"source"`
	Severity  store.Severity   `json:"severity"`
	ProbeOK   bool             `json:"probeOk"`
}

func (n *Notifier) sendGeneric(webhookURL string, findings []store.CertFinding) {
	payload := GenericPayload{
		Timestamp: time.Now().UTC(),
		Summary:   buildSummary(findings),
		Findings:  make([]GenericFinding, len(findings)),
	}
	for i := range findings {
		payload.Findings[i] = GenericFinding{
			Name:      findings[i].Name,
			Namespace: findings[i].Namespace,
			Source:    findings[i].Source,
			Severity:  findings[i].Severity,
			NotAfter:  findings[i].NotAfter,
			ProbeOK:   findings[i].ProbeOK,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("notification: marshal error", "err", err)
		return
	}

	n.post(webhookURL, "application/json", body)
}

// SlackPayload is the JSON body sent to Slack incoming webhooks.
type SlackPayload struct {
	Blocks []SlackBlock `json:"blocks"`
}

// SlackBlock is a Slack Block Kit block.
type SlackBlock struct {
	Text *SlackText `json:"text,omitempty"`
	Type string     `json:"type"`
}

// SlackText is a Slack text element.
type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (n *Notifier) sendSlack(webhookURL string, findings []store.CertFinding) {
	blocks := []SlackBlock{
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: fmt.Sprintf("trustwatch: %d new finding(s)", len(findings)),
			},
		},
	}

	for i := range findings {
		sevLabel := strings.ToUpper(string(findings[i].Severity))
		expiresIn := time.Until(findings[i].NotAfter).Truncate(time.Minute)
		var expiryText string
		if expiresIn <= 0 {
			expiryText = "EXPIRED"
		} else {
			expiryText = fmt.Sprintf("expires in %s", expiresIn)
		}

		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("[%s] *%s* in `%s` — %s",
					sevLabel, findings[i].Name, findings[i].Namespace, expiryText),
			},
		})
	}

	blocks = append(blocks, SlackBlock{
		Type: "context",
		Text: &SlackText{
			Type: "mrkdwn",
			Text: fmt.Sprintf("Source: trustwatch | %s", time.Now().UTC().Format(time.RFC3339)),
		},
	})

	payload := SlackPayload{Blocks: blocks}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("notification: slack marshal error", "err", err)
		return
	}

	n.post(webhookURL, "application/json", body)
}

func (n *Notifier) post(webhookURL, contentType string, body []byte) {
	resp, err := n.client.Post(webhookURL, contentType, bytes.NewReader(body)) //nolint:noctx // fire-and-forget notification
	if err != nil {
		slog.Warn("notification: webhook delivery failed", "url", webhookURL, "err", err)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close
	if resp.StatusCode >= 300 {
		slog.Warn("notification: webhook returned non-2xx", "url", webhookURL, "status", resp.StatusCode)
	}
}

func buildSummary(findings []store.CertFinding) string {
	var critCount, warnCount int
	for i := range findings {
		switch findings[i].Severity {
		case store.SeverityCritical:
			critCount++
		case store.SeverityWarn:
			warnCount++
		}
	}
	var parts []string
	if critCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critCount))
	}
	if warnCount > 0 {
		parts = append(parts, fmt.Sprintf("%d warn", warnCount))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d finding(s)", len(findings))
	}
	return strings.Join(parts, ", ") + " finding(s)"
}
