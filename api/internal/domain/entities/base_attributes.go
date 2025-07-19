package entities

import (
	"gorm.io/gorm"
	"time"
)

// Base structure for GORM models
type Base struct {
	ID        int            `gorm:"column:id;unique;primaryKey;not null"`
	UUID      string         `gorm:"column:uuid;type:varchar(255);unique;not null;default:uuid_generate_v4()"`
	CreatedAt time.Time      `gorm:"column:created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index"`
}
