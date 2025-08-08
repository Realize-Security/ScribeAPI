package entities

import "time"

// Base structure for GORM models
type Base struct {
	ID        int        `db:"id"`
	UUID      string     `db:"uuid"`
	CreatedAt time.Time  `db:"created_at"`
	UpdatedAt time.Time  `db:"updated_at"`
	DeletedAt *time.Time `db:"deleted_at"`
}
