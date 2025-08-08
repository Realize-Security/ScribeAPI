package database

import (
	"Scribe/pkg/config"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var (
	Db           *sqlx.DB
	sqlDB        *sql.DB
	dbConnectErr = "failed to connect to database: %v"
)

type Config struct {
	MaxIdle             int
	MaxOpen             int
	ConnMaxLifetime     time.Duration
	HealthCheckInterval time.Duration
}

func ConnectDB(cfg Config) error {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_DB"))

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		log.Printf(dbConnectErr, err)
		return fmt.Errorf(dbConnectErr, err)
	}

	sqlDB = db.DB
	sqlDB.SetMaxIdleConns(cfg.MaxIdle)
	sqlDB.SetMaxOpenConns(cfg.MaxOpen)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	Db = db
	return nil
}

func DBHealthMonitor(cfg Config) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), config.DBHealthCheckInterval)
		if err := sqlDB.PingContext(ctx); err != nil {
			log.Printf("Database health check failed: %v", err)
		}
		cancel()
		time.Sleep(cfg.HealthCheckInterval)
	}
}

func MigrateDb(db *sqlx.DB) {
	log.Println("Migrating database...")

	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		log.Fatalf("failed to create migrate driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://migrations", os.Getenv("POSTGRES_DB"), driver) // "postgres" is the database name placeholder
	if err != nil {
		log.Fatalf("failed to init migrate: %v", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("migration failed: %v", err)
	}
	log.Println("Database migration succeeded.")
}
