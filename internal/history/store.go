// Package history provides persistent snapshot storage using SQLite.
package history

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // CGO-free SQLite driver

	"github.com/ppiankov/trustwatch/internal/store"
)

// SnapshotSummary is a compact representation of a historical snapshot.
type SnapshotSummary struct {
	At            time.Time `json:"at"`
	ID            int64     `json:"id"`
	FindingsCount int       `json:"findingsCount"`
	CritCount     int       `json:"critCount"`
	WarnCount     int       `json:"warnCount"`
	ErrorCount    int       `json:"errorCount"`
}

// TrendPoint represents a single data point for trend analysis.
type TrendPoint struct {
	At       time.Time `json:"at"`
	Severity string    `json:"severity"`
	ProbeOK  bool      `json:"probeOk"`
}

// Store persists snapshots and findings to SQLite.
type Store struct {
	db *sql.DB
}

// Open creates or opens a SQLite database at the given path and runs migrations.
// Use ":memory:" for an in-memory database (useful for tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close() //nolint:errcheck // best-effort cleanup
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close() //nolint:errcheck // best-effort cleanup
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Save persists a snapshot and its findings to the database.
func (s *Store) Save(snap store.Snapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit below; rollback is no-op after commit

	var critCount, warnCount, errCount int
	for i := range snap.Findings {
		switch snap.Findings[i].Severity {
		case store.SeverityCritical:
			critCount++
		case store.SeverityWarn:
			warnCount++
		}
		if !snap.Findings[i].ProbeOK {
			errCount++
		}
	}

	result, err := tx.Exec(
		"INSERT INTO snapshots (at, findings_count, crit_count, warn_count, error_count) VALUES (?, ?, ?, ?, ?)",
		snap.At, len(snap.Findings), critCount, warnCount, errCount,
	)
	if err != nil {
		return fmt.Errorf("inserting snapshot: %w", err)
	}

	snapID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting snapshot id: %w", err)
	}

	stmt, err := tx.Prepare(
		"INSERT INTO findings (snapshot_id, source, namespace, name, severity, not_after, probe_ok, finding_type, serial, issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		return fmt.Errorf("preparing finding insert: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // statement lifetime bounded by tx

	for i := range snap.Findings {
		f := &snap.Findings[i]
		_, err := stmt.Exec(snapID, f.Source, f.Namespace, f.Name, f.Severity, f.NotAfter, f.ProbeOK, f.FindingType, f.Serial, f.Issuer)
		if err != nil {
			return fmt.Errorf("inserting finding: %w", err)
		}
	}

	return tx.Commit()
}

// List returns the most recent snapshot summaries, ordered newest first.
func (s *Store) List(limit int) ([]SnapshotSummary, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(
		"SELECT id, at, findings_count, crit_count, warn_count, error_count FROM snapshots ORDER BY at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying snapshots: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var summaries []SnapshotSummary
	for rows.Next() {
		var s SnapshotSummary
		if err := rows.Scan(&s.ID, &s.At, &s.FindingsCount, &s.CritCount, &s.WarnCount, &s.ErrorCount); err != nil {
			return nil, fmt.Errorf("scanning snapshot: %w", err)
		}
		summaries = append(summaries, s)
	}
	return summaries, rows.Err()
}

// Trend returns severity data points for a specific finding over time.
func (s *Store) Trend(name, ns, source string, limit int) ([]TrendPoint, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(`
		SELECT s.at, f.severity, f.probe_ok
		FROM findings f
		JOIN snapshots s ON s.id = f.snapshot_id
		WHERE f.name = ? AND f.namespace = ? AND f.source = ?
		ORDER BY s.at DESC
		LIMIT ?`,
		name, ns, source, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying trend: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.At, &p.Severity, &p.ProbeOK); err != nil {
			return nil, fmt.Errorf("scanning trend point: %w", err)
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// GetLatest returns the most recent snapshot with its findings, or nil if no snapshots exist.
func (s *Store) GetLatest() (*store.Snapshot, error) {
	var snapID int64
	var at time.Time
	err := s.db.QueryRow("SELECT id, at FROM snapshots ORDER BY at DESC LIMIT 1").Scan(&snapID, &at)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying latest snapshot: %w", err)
	}

	rows, err := s.db.Query(
		"SELECT source, namespace, name, severity, not_after, probe_ok, finding_type, serial, issuer FROM findings WHERE snapshot_id = ?",
		snapID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	snap := &store.Snapshot{At: at}
	for rows.Next() {
		var f store.CertFinding
		if err := rows.Scan(&f.Source, &f.Namespace, &f.Name, &f.Severity, &f.NotAfter, &f.ProbeOK, &f.FindingType, &f.Serial, &f.Issuer); err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}
		snap.Findings = append(snap.Findings, f)
	}
	return snap, rows.Err()
}
