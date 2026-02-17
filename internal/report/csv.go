package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

var csvHeader = []string{
	"name", "namespace", "source", "severity", "notAfter",
	"issuer", "serial", "findingType", "remediation", "probeOk",
}

// WriteCSV writes findings as CSV rows to w.
func WriteCSV(w io.Writer, findings []store.CertFinding) error {
	cw := csv.NewWriter(w)

	if err := cw.Write(csvHeader); err != nil {
		return err
	}

	for i := range findings {
		f := &findings[i]
		notAfter := ""
		if !f.NotAfter.IsZero() {
			notAfter = f.NotAfter.UTC().Format(time.RFC3339)
		}
		row := []string{
			f.Name,
			f.Namespace,
			string(f.Source),
			string(f.Severity),
			notAfter,
			f.Issuer,
			f.Serial,
			f.FindingType,
			f.Remediation,
			strconv.FormatBool(f.ProbeOK),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}
