package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrate applies all pending SQL migration files in order.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version    INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("migrate: create schema_version: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("migrate: read migrations dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version := migrationVersion(entry.Name())

		var count int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_version WHERE version = ?", version,
		).Scan(&count); err != nil {
			return fmt.Errorf("migrate: check version %d: %w", version, err)
		}
		if count > 0 {
			continue // already applied
		}

		data, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", entry.Name(), err)
		}

		// Split on semicolons and execute each statement individually.
		// Required for Turso/libSQL which only executes the first statement per ExecContext call.
		for _, stmt := range strings.Split(string(data), ";") {
			lines := strings.Split(stmt, "\n")
			var clean []string
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "--") {
					continue
				}
				clean = append(clean, line)
			}
			stmt = strings.TrimSpace(strings.Join(clean, "\n"))
			if stmt == "" {
				continue
			}
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate: apply %s: %w", entry.Name(), err)
			}
		}

		if _, err := db.ExecContext(ctx,
			"INSERT INTO schema_version (version, applied_at) VALUES (?, strftime('%s', 'now'))",
			version,
		); err != nil {
			return fmt.Errorf("migrate: record version %d: %w", version, err)
		}
	}
	return nil
}

func migrationVersion(filename string) int {
	var v int
	_, _ = fmt.Sscanf(filename, "%d_", &v)
	return v
}
