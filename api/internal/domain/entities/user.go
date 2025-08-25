package entities

import (
	"time"
)

type UserDBModel struct {
	ID                 int64          `db:"id"`
	UUID               string         `db:"uuid"`
	CreatedAt          time.Time      `db:"created_at"`
	UpdatedAt          time.Time      `db:"updated_at"`
	DeletedAt          *time.Time     `db:"deleted_at"`
	FirstName          string         `db:"first_name" validate:"required"`
	LastName           string         `db:"last_name" validate:"required"`
	Email              string         `db:"email" validate:"required,email"`
	Password           string         `db:"password" validate:"required"`
	IsActive           bool           `db:"is_active"`
	TermsAccepted      bool           `db:"terms_accepted" validate:"required"`
	PasswordResetToken *string        `db:"password_reset_token"`
	OrganisationID     *string        `db:"organisation_id"`
	Roles              []*RoleDBModel `db:"-"`
}
