package entities

import (
	"time"

	"github.com/lib/pq"
)

type OrganisationDBModel struct {
	ID                 int64          `db:"id"`
	UUID               string         `db:"uuid"`
	CreatedAt          time.Time      `db:"created_at"`
	UpdatedAt          time.Time      `db:"updated_at"`
	DeletedAt          *time.Time     `db:"deleted_at"`
	Name               string         `db:"name" validate:"required"`
	PrimaryContactID   int64          `db:"primary_contact_id" validate:"required"`
	SecondaryContactID int64          `db:"secondary_contact_id"`
	PrimaryDomain      string         `db:"primary_domain" validate:"required"`
	AllowedDomains     pq.StringArray `db:"allowed_domains" validate:"required"`
	MFAEnabled         bool           `db:"mfa_enabled" validate:"required"`
	IsValidated        bool           `db:"is_validated"`
}
