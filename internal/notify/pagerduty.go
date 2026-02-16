package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/store"
)

// pagerDutyEventsURL is the PagerDuty Events API v2 endpoint (var for testing).
var pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue" //nolint:gosec // not a credential

// pdEvent is a PagerDuty Events API v2 request body.
type pdEvent struct {
	Payload     *pdPayload `json:"payload,omitempty"`
	RoutingKey  string     `json:"routing_key"`
	EventAction string     `json:"event_action"`
	DedupKey    string     `json:"dedup_key"`
}

// pdPayload is the payload section of a PagerDuty trigger event.
type pdPayload struct {
	Timestamp time.Time `json:"timestamp"`
	Summary   string    `json:"summary"`
	Source    string    `json:"source"`
	Severity  string    `json:"severity"`
}

func (n *Notifier) sendPagerDuty(wh config.WebhookConfig, findings []store.CertFinding) {
	for i := range findings {
		f := &findings[i]
		event := pdEvent{
			RoutingKey:  wh.RoutingKey,
			EventAction: "trigger",
			DedupKey:    findingKey(f),
			Payload: &pdPayload{
				Summary:   pdSummary(f),
				Source:    "trustwatch",
				Severity:  pdSeverity(f.Severity),
				Timestamp: time.Now().UTC(),
			},
		}

		body, err := json.Marshal(event)
		if err != nil {
			continue
		}
		n.post(pagerDutyEventsURL, "application/json", body)
	}
}

func (n *Notifier) resolvePagerDuty(wh config.WebhookConfig, keys []string) {
	for _, key := range keys {
		event := pdEvent{
			RoutingKey:  wh.RoutingKey,
			EventAction: "resolve",
			DedupKey:    key,
		}

		body, err := json.Marshal(event)
		if err != nil {
			continue
		}
		n.post(pagerDutyEventsURL, "application/json", body)
	}
}

func pdSummary(f *store.CertFinding) string {
	where := f.Name
	if f.Namespace != "" {
		where = f.Namespace + "/" + f.Name
	}
	return fmt.Sprintf("[%s] %s — %s",
		strings.ToUpper(string(f.Severity)), where, string(f.Source))
}

func pdSeverity(s store.Severity) string {
	switch s {
	case store.SeverityCritical:
		return "critical"
	case store.SeverityWarn:
		return "warning"
	default:
		return "info"
	}
}
