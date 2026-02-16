// Package web provides HTTP handlers for the trustwatch web UI and API.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

//go:embed templates/problems.html
var templateFS embed.FS

var problemsTmpl = template.Must(template.ParseFS(templateFS, "templates/problems.html"))

// SnapshotFunc returns the current snapshot.
type SnapshotFunc func() store.Snapshot

// UIConfig holds options for UIHandler.
type UIConfig struct {
	historyEnabled bool
}

// WithHistoryEnabled marks that the /api/v1/trend endpoint is available.
func WithHistoryEnabled() func(*UIConfig) {
	return func(c *UIConfig) {
		c.historyEnabled = true
	}
}

// UIHandler serves the problems web UI, filtering to critical+warn only.
func UIHandler(getSnapshot SnapshotFunc, opts ...func(*UIConfig)) http.HandlerFunc {
	cfg := &UIConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		snap := getSnapshot()
		now := time.Now()

		// Filter to critical and warn only (info is inventory noise)
		var problems []store.CertFinding
		for i := range snap.Findings {
			if snap.Findings[i].Severity == store.SeverityCritical || snap.Findings[i].Severity == store.SeverityWarn {
				problems = append(problems, snap.Findings[i])
			}
		}

		// Sort: critical first, then warn; within severity, earliest expiry first
		sort.Slice(problems, func(i, j int) bool {
			si, sj := sevOrder(problems[i].Severity), sevOrder(problems[j].Severity)
			if si != sj {
				return si < sj
			}
			return problems[i].NotAfter.Before(problems[j].NotAfter)
		})

		// Build template data
		var critCount, warnCount int
		rows := make([]findingRow, 0, len(problems))
		for i := range problems {
			f := &problems[i]
			switch f.Severity {
			case store.SeverityCritical:
				critCount++
			case store.SeverityWarn:
				warnCount++
			}
			rows = append(rows, findingRow{
				Severity:         string(f.Severity),
				SevClass:         string(f.Severity),
				Source:           string(f.Source),
				Where:            formatWhere(f),
				ExpiresIn:        formatExpiresIn(f.NotAfter, now),
				NotAfter:         formatNotAfter(f.NotAfter),
				Risk:             f.Notes,
				ChainErrors:      strings.Join(f.ChainErrors, "; "),
				PostureIssues:    strings.Join(f.PostureIssues, "; "),
				RevocationIssues: strings.Join(f.RevocationIssues, "; "),
				Error:            f.ProbeErr,
				Subject:          f.Subject,
				Issuer:           f.Issuer,
				Serial:           f.Serial,
				DNSNames:         strings.Join(f.DNSNames, ", "),
				KeyAlgorithm:     f.KeyAlgorithm,
				TLSVersion:       f.TLSVersion,
				CipherSuite:      f.CipherSuite,
				FindingType:      f.FindingType,
				PolicyName:       f.PolicyName,
				Name:             f.Name,
				Namespace:        f.Namespace,
				Cluster:          f.Cluster,
				Remediation:      f.Remediation,
			})
		}

		data := pageData{
			ScanTime:       snap.At.Format(time.RFC3339),
			CriticalCount:  critCount,
			WarnCount:      warnCount,
			Findings:       rows,
			HistoryEnabled: cfg.historyEnabled,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := problemsTmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// SnapshotHandler returns the full snapshot as JSON.
func SnapshotHandler(getSnapshot SnapshotFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snap := getSnapshot()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snap); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// HealthzHandler returns 200 when a scan has completed within maxAge, 503 otherwise.
// A zero maxAge disables staleness checks (always healthy if any scan completed).
func HealthzHandler(getSnapshot SnapshotFunc, maxAge time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		snap := getSnapshot()

		if snap.At.IsZero() {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("no scan completed")) //nolint:errcheck // best-effort response body
			return
		}

		if maxAge > 0 && time.Since(snap.At) > maxAge {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("scan stale")) //nolint:errcheck // best-effort response body
			return
		}

		w.Write([]byte("ok")) //nolint:errcheck // best-effort response body
	}
}

type pageData struct {
	ScanTime       string
	Findings       []findingRow
	CriticalCount  int
	WarnCount      int
	HistoryEnabled bool
}

type findingRow struct {
	Severity         string
	SevClass         string
	Source           string
	Where            string
	ExpiresIn        string
	NotAfter         string
	Risk             string
	ChainErrors      string
	PostureIssues    string
	RevocationIssues string
	Error            string
	Subject          string
	Issuer           string
	Serial           string
	DNSNames         string
	KeyAlgorithm     string
	TLSVersion       string
	CipherSuite      string
	FindingType      string
	PolicyName       string
	Name             string
	Namespace        string
	Cluster          string
	Remediation      string
}

func sevOrder(s store.Severity) int {
	switch s {
	case store.SeverityCritical:
		return 0
	case store.SeverityWarn:
		return 1
	default:
		return 2
	}
}

func formatWhere(f *store.CertFinding) string {
	if f.Namespace != "" && f.Name != "" {
		return f.Namespace + "/" + f.Name
	}
	if f.Name != "" {
		return f.Name
	}
	return f.Target
}

// formatExpiresIn returns a human-readable relative time without terminal styling.
func formatExpiresIn(notAfter, now time.Time) string {
	if notAfter.IsZero() {
		return ""
	}
	d := notAfter.Sub(now)
	if d < 0 {
		return "EXPIRED"
	}
	days := int(math.Floor(d.Hours() / 24))
	hours := int(math.Floor(d.Hours())) % 24
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

func formatNotAfter(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04 UTC")
}
