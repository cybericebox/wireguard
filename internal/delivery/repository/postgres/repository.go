package postgres

import (
	"errors"
	"fmt"
	"github.com/cybericebox/wireguard/internal/config"
	"github.com/golang-migrate/migrate/v4"
	pg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

const migrationTable = "wireguard_schema_migrations"

type (
	PostgresRepository struct {
		*Queries
		db *sqlx.DB
	}
)

func NewRepository(config *config.PostgresConfig) *PostgresRepository {
	db, err := newPostgresDB(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create new postgres db connection")
	}

	if err = runMigrations(db, config.Database); err != nil {
		log.Fatal().Err(err).Msg("Failed to run db migrations")
	}

	return &PostgresRepository{
		Queries: New(db),
		db:      db,
	}
}

func newPostgresDB(cfg *config.PostgresConfig) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=%s",
		cfg.Username, cfg.Password, cfg.Database, cfg.Host, cfg.Port, cfg.SSLMode))
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func runMigrations(db *sqlx.DB, dbName string) error {
	driver, err := pg.WithInstance(db.DB, &pg.Config{
		MigrationsTable: migrationTable,
	})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", config.MigrationPath),
		dbName,
		driver,
	)
	if err != nil {
		return err
	}

	if err = m.Up(); err != nil {
		if !errors.Is(migrate.ErrNoChange, err) {
			return err
		}
	}
	return nil
}
