//go:build integration

package repository_test

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("enabling foreign keys: %v", err)
	}

	migration, err := os.ReadFile("../../../migrations/init.sql")
	if err != nil {
		t.Fatalf("reading migration: %v", err)
	}

	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatalf("running migration: %v", err)
	}

	t.Cleanup(func() { db.Close() })

	return db
}
