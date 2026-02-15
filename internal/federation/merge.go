package federation

import (
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Merge combines a local snapshot with remote snapshots, adding the cluster
// label to all findings.
func Merge(localName string, local store.Snapshot, remotes map[string]store.Snapshot) store.Snapshot {
	// Label local findings
	for i := range local.Findings {
		local.Findings[i].Cluster = localName
	}

	// Append remote findings with cluster labels
	for clusterName, remote := range remotes {
		for i := range remote.Findings {
			remote.Findings[i].Cluster = clusterName
		}
		local.Findings = append(local.Findings, remote.Findings...)
	}

	// Use latest timestamp
	local.At = time.Now().UTC()

	return local
}
