package entities

import (
	"time"

	"github.com/lib/pq"
)

type OrganisationDBModel struct {
	ID                    int            `db:"id"`
	UUID                  string         `db:"uuid"`
	CreatedAt             time.Time      `db:"created_at"`
	UpdatedAt             time.Time      `db:"updated_at"`
	DeletedAt             *time.Time     `db:"deleted_at"`
	Name                  string         `db:"name" json:"name" validate:"required"`
	PrimaryContactName    string         `db:"primary_contact_name" json:"primaryContactName" validate:"required"`
	PrimaryContactEmail   string         `db:"primary_contact_email" json:"primaryContactEmail" validate:"required,email"`
	PrimaryContactPhone   string         `db:"primary_contact_phone" json:"primaryContactPhone" validate:"required"`
	SecondaryContactName  string         `db:"secondary_contact_name" json:"secondaryContactName"`
	SecondaryContactEmail string         `db:"secondary_contact_email" json:"secondaryContactEmail" validate:"email"`
	SecondaryContactPhone string         `db:"secondary_contact_phone" json:"secondaryContactPhone"`
	PrimaryDomain         string         `db:"primary_domain" json:"primaryDomain" validate:"required"`
	AllowedDomains        pq.StringArray `db:"allowed_domains" json:"allowedDomains" validate:"required"`
	MFAEnabled            bool           `db:"mfa_enabled" json:"mfaEnabled" validate:"required"`
	IsValidated           bool           `db:"is_validated"`
	IsMaster              bool           `db:"is_master"`
}
