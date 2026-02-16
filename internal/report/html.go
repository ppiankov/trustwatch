// Package report generates self-contained HTML compliance reports from scan snapshots.
package report

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

//go:embed templates/report.html
var templateFS embed.FS

var reportTmpl = template.Must(template.ParseFS(templateFS, "templates/report.html"))

// Generate renders a scan snapshot as a self-contained HTML report.
func Generate(snap store.Snapshot, clusterName string) ([]byte, error) {
	findings := sortFindings(snap.Findings)

	var critCount, warnCount, infoCount int
	rows := make([]reportRow, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		switch f.Severity {
		case store.SeverityCritical:
			critCount++
		case store.SeverityWarn:
			warnCount++
		default:
			infoCount++
		}
		rows = append(rows, buildRow(f, snap.At))
	}

	data := reportData{
		ScanTime:      snap.At.UTC().Format("2006-01-02 15:04 UTC"),
		ClusterName:   clusterName,
		CriticalCount: critCount,
		WarnCount:     warnCount,
		InfoCount:     infoCount,
		TotalCount:    len(findings),
		Findings:      rows,
	}

	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type reportData struct {
	ScanTime      string
	ClusterName   string
	Findings      []reportRow
	CriticalCount int
	WarnCount     int
	InfoCount     int
	TotalCount    int
}

type reportRow struct {
	Severity         string
	SeverityLabel    string
	Source           string
	Where            string
	ExpiresIn        string
	NotAfter         string
	Issue            string
	Subject          string
	Issuer           string
	Serial           string
	DNSNames         string
	KeyAlgorithm     string
	TLSVersion       string
	CipherSuite      string
	ChainErrors      string
	PostureIssues    string
	RevocationIssues string
	FindingType      string
	Error            string
	Remediation      string
}

func buildRow(f *store.CertFinding, now time.Time) reportRow {
	where := f.Name
	if f.Namespace != "" {
		where = f.Namespace + "/" + f.Name
	}

	var sevLabel string
	switch f.Severity {
	case store.SeverityCritical:
		sevLabel = "CRITICAL"
	case store.SeverityWarn:
		sevLabel = "WARN"
	default:
		sevLabel = "INFO"
	}

	var issue string
	switch {
	case f.ProbeErr != "":
		issue = f.ProbeErr
	case len(f.RevocationIssues) > 0:
		issue = strings.Join(f.RevocationIssues, "; ")
	case len(f.ChainErrors) > 0:
		issue = strings.Join(f.ChainErrors, "; ")
	case len(f.PostureIssues) > 0:
		issue = strings.Join(f.PostureIssues, "; ")
	case f.Notes != "":
		issue = f.Notes
	}

	var expiresIn, notAfter string
	if !f.NotAfter.IsZero() {
		expiresIn = formatExpiresIn(f.NotAfter, now)
		notAfter = f.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	}

	return reportRow{
		Severity:         string(f.Severity),
		SeverityLabel:    sevLabel,
		Source:           string(f.Source),
		Where:            where,
		ExpiresIn:        expiresIn,
		NotAfter:         notAfter,
		Issue:            issue,
		Subject:          f.Subject,
		Issuer:           f.Issuer,
		Serial:           f.Serial,
		DNSNames:         strings.Join(f.DNSNames, ", "),
		KeyAlgorithm:     f.KeyAlgorithm,
		TLSVersion:       f.TLSVersion,
		CipherSuite:      f.CipherSuite,
		ChainErrors:      strings.Join(f.ChainErrors, "; "),
		PostureIssues:    strings.Join(f.PostureIssues, "; "),
		RevocationIssues: strings.Join(f.RevocationIssues, "; "),
		FindingType:      f.FindingType,
		Error:            f.ProbeErr,
		Remediation:      f.Remediation,
	}
}

func formatExpiresIn(notAfter, now time.Time) string {
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

func sortFindings(findings []store.CertFinding) []store.CertFinding {
	sorted := make([]store.CertFinding, len(findings))
	copy(sorted, findings)

	sevOrder := map[store.Severity]int{
		store.SeverityCritical: 0,
		store.SeverityWarn:     1,
		store.SeverityInfo:     2,
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := sevOrder[sorted[i].Severity], sevOrder[sorted[j].Severity]
		if si != sj {
			return si < sj
		}
		return sorted[i].NotAfter.Before(sorted[j].NotAfter)
	})

	return sorted
}
