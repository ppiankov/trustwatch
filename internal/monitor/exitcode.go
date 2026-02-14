// Package monitor provides TUI rendering and exit-code logic for trustwatch.
package monitor

import "github.com/ppiankov/trustwatch/internal/store"

// ExitCode returns a process exit code based on the worst finding in a snapshot.
//
//	0 = no problems
//	1 = warnings exist
//	2 = critical problems
//	3 = discovery/probe errors
func ExitCode(snap store.Snapshot) int {
	if len(snap.Errors) > 0 {
		return 3
	}
	code := 0
	for i := range snap.Findings {
		if !snap.Findings[i].ProbeOK {
			return 3
		}
		switch snap.Findings[i].Severity {
		case store.SeverityCritical:
			code = 2
		case store.SeverityWarn:
			if code < 1 {
				code = 1
			}
		}
	}
	return code
}
