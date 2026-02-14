package monitor

import (
	"encoding/json"
	"io"

	"github.com/ppiankov/trustwatch/internal/store"
)

// NowOutput is the JSON envelope for `trustwatch now --output json`.
// Wraps the snapshot with exit-code metadata without polluting the
// Snapshot type used by the serve-mode /api/v1/snapshot endpoint.
type NowOutput struct {
	Snapshot store.Snapshot `json:"snapshot"`
	ExitCode int            `json:"exitCode"`
}

// WriteJSON serializes a NowOutput envelope to w.
func WriteJSON(w io.Writer, snap store.Snapshot, exitCode int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(NowOutput{
		ExitCode: exitCode,
		Snapshot: snap,
	})
}
