package history

import (
	"database/sql"
	"strings"
)

const schema = `
CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             DATETIME NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    crit_count     INTEGER NOT NULL DEFAULT 0,
    warn_count     INTEGER NOT NULL DEFAULT 0,
    error_count    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    source      TEXT NOT NULL DEFAULT '',
    namespace   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    not_after   DATETIME,
    probe_ok    BOOLEAN NOT NULL DEFAULT 0,
    finding_type TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_snapshot ON findings(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_findings_trend ON findings(source, namespace, name);
`

func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// v2: add serial and issuer columns for drift detection (idempotent)
	for _, stmt := range []string{
		"ALTER TABLE findings ADD COLUMN serial TEXT DEFAULT ''",
		"ALTER TABLE findings ADD COLUMN issuer TEXT DEFAULT ''",
	} {
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumn(err) {
			return err
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	// SQLite returns "duplicate column name" when the column already exists.
	msg := err.Error()
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}
