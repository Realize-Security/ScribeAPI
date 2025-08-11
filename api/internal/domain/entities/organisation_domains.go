package entities

import "time"

// OrganisationDomainDBModel contains domains associated with a given organisation.
// These can be both allow listed and deny listed domains.
type OrganisationDomainDBModel struct {
	ID             int64      `db:"id"`
	UUID           string     `db:"uuid"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
	DeletedAt      *time.Time `db:"deleted_at"`
	Domain         string     `db:"domain" json:"domain" binding:"required" validate:"required"`
	IsValidated    bool       `db:"is_validated"`
	AllowList      bool       `db:"allow_list"`
	OrganisationID *int64     `db:"organisation_id"`
}
