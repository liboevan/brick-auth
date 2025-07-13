package database

import (
	"database/sql"
	"fmt"
	"log"
)

// Migration represents a database migration
type Migration struct {
	Version int    `db:"version"`
	SQL     string `db:"sql"`
}

// Migrator handles database migrations
type Migrator struct {
	db *sql.DB
}

// NewMigrator creates a new migrator
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate() error {
	// Create migrations table if it doesn't exist
	if err := m.createMigrationsTable(); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get current version
	currentVersion, err := m.getCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Get all migrations
	migrations := m.getMigrations()

	// Run pending migrations
	for _, migration := range migrations {
		if migration.Version > currentVersion {
			log.Printf("Running migration version %d", migration.Version)
			
			if err := m.runMigration(migration); err != nil {
				return fmt.Errorf("failed to run migration %d: %w", migration.Version, err)
			}

			if err := m.updateVersion(migration.Version); err != nil {
				return fmt.Errorf("failed to update version: %w", err)
			}

			log.Printf("Migration version %d completed", migration.Version)
		}
	}

	return nil
}

// createMigrationsTable creates the migrations table
func (m *Migrator) createMigrationsTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`
	_, err := m.db.Exec(query)
	return err
}

// getCurrentVersion gets the current migration version
func (m *Migrator) getCurrentVersion() (int, error) {
	query := `SELECT COALESCE(MAX(version), 0) FROM migrations`
	var version int
	err := m.db.QueryRow(query).Scan(&version)
	return version, err
}

// updateVersion updates the current migration version
func (m *Migrator) updateVersion(version int) error {
	query := `INSERT INTO migrations (version) VALUES (?)`
	_, err := m.db.Exec(query, version)
	return err
}

// runMigration runs a single migration
func (m *Migrator) runMigration(migration *Migration) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(migration.SQL)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// getMigrations returns all migrations in order
func (m *Migrator) getMigrations() []*Migration {
	return []*Migration{
		{
			Version: 1,
			SQL: `
				CREATE TABLE IF NOT EXISTS users (
					id TEXT PRIMARY KEY,
					username TEXT UNIQUE NOT NULL,
					password TEXT NOT NULL,
					email TEXT UNIQUE NOT NULL,
					active BOOLEAN DEFAULT TRUE,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			`,
		},
		{
			Version: 2,
			SQL: `
				CREATE TABLE IF NOT EXISTS roles (
					id TEXT PRIMARY KEY,
					name TEXT UNIQUE NOT NULL,
					description TEXT,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			`,
		},
		{
			Version: 3,
			SQL: `
				CREATE TABLE IF NOT EXISTS permissions (
					id TEXT PRIMARY KEY,
					name TEXT UNIQUE NOT NULL,
					description TEXT,
					resource TEXT NOT NULL,
					action TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			`,
		},
		{
			Version: 4,
			SQL: `
				CREATE TABLE IF NOT EXISTS user_roles (
					user_id TEXT NOT NULL,
					role_id TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY (user_id, role_id),
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
					FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
				)
			`,
		},
		{
			Version: 5,
			SQL: `
				CREATE TABLE IF NOT EXISTS role_permissions (
					role_id TEXT NOT NULL,
					permission_id TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY (role_id, permission_id),
					FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
					FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
				)
			`,
		},
	}
} 