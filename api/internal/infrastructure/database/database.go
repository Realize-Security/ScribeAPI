package database

import (
	"Scribe/pkg/config"
	"context"
	"database/sql"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
	"time"
)

var (
	Db           *gorm.DB
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
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("POSTGRES_PASSWORD"))

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf(dbConnectErr, err)
		return fmt.Errorf(dbConnectErr, err)
	}

	sqlDB, err = db.DB()
	if err != nil {
		log.Printf("failed to get underlying *sql.DB: %v", err)
		return nil
	}

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
