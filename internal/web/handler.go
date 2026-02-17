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
	return func(w http.ResponseWriter, r *http.Request) {
		snap := getSnapshot()
		now := time.Now()

		// Apply query param filters first
		filtered := filterFindings(snap.Findings, r)

		// Filter to critical and warn only (info is inventory noise)
		var problems []store.CertFinding
		for i := range filtered {
			if filtered[i].Severity == store.SeverityCritical || filtered[i].Severity == store.SeverityWarn {
				problems = append(problems, filtered[i])
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
// Accepts optional query params: ?source=, ?severity=, ?namespace= (comma-separated).
func SnapshotHandler(getSnapshot SnapshotFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := getSnapshot()
		snap.Findings = filterFindings(snap.Findings, r)
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

type readyzResponse struct {
	LastScan        string   `json:"lastScan"`
	ScanAge         string   `json:"scanAge"`
	DiscoveryErrors []string `json:"discoveryErrors,omitempty"`
	FindingsCount   int      `json:"findingsCount"`
	Ready           bool     `json:"ready"`
}

// ReadyzHandler returns JSON readiness detail.
// Returns 200 when scan is fresh, 503 when stale or no scan completed.
func ReadyzHandler(getSnapshot SnapshotFunc, maxAge time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snap := getSnapshot()

		resp := readyzResponse{
			FindingsCount: len(snap.Findings),
		}

		if !snap.At.IsZero() {
			resp.LastScan = snap.At.Format(time.RFC3339)
			resp.ScanAge = time.Since(snap.At).Truncate(time.Second).String()
		}

		for source, errMsg := range snap.Errors {
			resp.DiscoveryErrors = append(resp.DiscoveryErrors, source+": "+errMsg)
		}

		resp.Ready = !snap.At.IsZero() && (maxAge <= 0 || time.Since(snap.At) <= maxAge)

		if !resp.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(resp) //nolint:errcheck // best-effort response body
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

// filterFindings applies ?source=, ?severity=, ?namespace= query param filters as AND conditions.
// Multiple values within a param are comma-separated and OR'd.
func filterFindings(findings []store.CertFinding, r *http.Request) []store.CertFinding {
	q := r.URL.Query()
	sources := splitParam(q.Get("source"))
	severities := splitParam(q.Get("severity"))
	namespaces := splitParam(q.Get("namespace"))

	if len(sources) == 0 && len(severities) == 0 && len(namespaces) == 0 {
		return findings
	}

	filtered := make([]store.CertFinding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		if len(sources) > 0 && !contains(sources, string(f.Source)) {
			continue
		}
		if len(severities) > 0 && !contains(severities, string(f.Severity)) {
			continue
		}
		if len(namespaces) > 0 && !contains(namespaces, f.Namespace) {
			continue
		}
		filtered = append(filtered, *f)
	}
	return filtered
}

func splitParam(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			result = append(result, s)
		}
	}
	return result
}

func contains(set []string, val string) bool {
	for _, s := range set {
		if s == val {
			return true
		}
	}
	return false
}
