package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestRemoteSource_Fetch(t *testing.T) {
	snap := store.Snapshot{
		At: time.Now().UTC().Truncate(time.Second),
		Findings: []store.CertFinding{
			{Name: "remote-cert", Source: store.SourceWebhook, Severity: store.SeverityWarn, ProbeOK: true},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	remote := &RemoteSource{Name: "remote-cluster", URL: srv.URL}
	result, err := remote.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Name != "remote-cert" {
		t.Errorf("name = %q, want %q", result.Findings[0].Name, "remote-cert")
	}
}

func TestRemoteSource_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	remote := &RemoteSource{Name: "bad-cluster", URL: srv.URL}
	_, err := remote.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}
