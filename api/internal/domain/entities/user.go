package entities

import (
	"strings"
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

type UserRegistration struct {
	FirstName       string `json:"firstName" validate:"required,name_length,name_pattern"`
	LastName        string `json:"lastName" validate:"required,name_length,name_pattern"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,passwords_match,password_length"`
	ConfirmPassword string `json:"confirmPassword" validate:"required"`
	TermsAccepted   bool   `json:"termsAccepted,default:false" validate:"required"`
}

func (u *UserRegistration) Sanitize() {
	u.FirstName = strings.TrimSpace(u.FirstName)
	u.LastName = strings.TrimSpace(u.LastName)
	u.Email = strings.TrimSpace(strings.ToLower(u.Email))
}

type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
