package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ppiankov/trustwatch/internal/history"
)

// HistoryHandler returns the most recent snapshot summaries as JSON.
func HistoryHandler(hs *history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 {
				limit = n
			}
		}

		summaries, err := hs.List(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(summaries); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// TrendHandler returns trend data points for a specific finding as JSON.
func TrendHandler(hs *history.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")
		source := r.URL.Query().Get("source")

		if name == "" || source == "" {
			http.Error(w, "name and source query parameters are required", http.StatusBadRequest)
			return
		}

		limit := 50
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 {
				limit = n
			}
		}

		points, err := hs.Trend(name, ns, source, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(points); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
