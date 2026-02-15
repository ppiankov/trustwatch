// Package federation provides multi-cluster snapshot aggregation.
package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

const defaultTimeout = 15 * time.Second

// RemoteSource fetches a snapshot from a remote trustwatch instance.
type RemoteSource struct {
	Name string
	URL  string
}

// Fetch retrieves the snapshot from the remote /api/v1/snapshot endpoint.
func (r *RemoteSource) Fetch(ctx context.Context) (store.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL+"/api/v1/snapshot", http.NoBody)
	if err != nil {
		return store.Snapshot{}, fmt.Errorf("building request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return store.Snapshot{}, fmt.Errorf("fetching remote snapshot: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only

	if resp.StatusCode != http.StatusOK {
		return store.Snapshot{}, fmt.Errorf("remote returned status %d", resp.StatusCode)
	}

	var snap store.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return store.Snapshot{}, fmt.Errorf("decoding remote snapshot: %w", err)
	}

	return snap, nil
}
