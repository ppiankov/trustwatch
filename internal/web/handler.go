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
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

//go:embed templates/problems.html
var templateFS embed.FS

var problemsTmpl = template.Must(template.ParseFS(templateFS, "templates/problems.html"))

// SnapshotFunc returns the current snapshot.
type SnapshotFunc func() store.Snapshot

// UIHandler serves the problems web UI, filtering to critical+warn only.
func UIHandler(getSnapshot SnapshotFunc) http.HandlerFunc {
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
				Severity:  string(f.Severity),
				SevClass:  string(f.Severity),
				Source:    string(f.Source),
				Where:     formatWhere(f),
				ExpiresIn: formatExpiresIn(f.NotAfter, now),
				NotAfter:  formatNotAfter(f.NotAfter),
				Risk:      f.Notes,
				Error:     f.ProbeErr,
			})
		}

		data := pageData{
			ScanTime:      snap.At.Format(time.RFC3339),
			CriticalCount: critCount,
			WarnCount:     warnCount,
			Findings:      rows,
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

// HealthzHandler returns 200 with body "ok".
func HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok")) //nolint:errcheck // best-effort response
	}
}

type pageData struct {
	ScanTime      string
	Findings      []findingRow
	CriticalCount int
	WarnCount     int
}

type findingRow struct {
	Severity  string
	SevClass  string
	Source    string
	Where     string
	ExpiresIn string
	NotAfter  string
	Risk      string
	Error     string
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
