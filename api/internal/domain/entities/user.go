package entities

import "time"

type UserDBModel struct {
	ID                      int            `db:"id"`
	UUID                    string         `db:"uuid"`
	CreatedAt               time.Time      `db:"created_at"`
	UpdatedAt               time.Time      `db:"updated_at"`
	DeletedAt               *time.Time     `db:"deleted_at"`
	FirstName               string         `db:"first_name" validate:"required"`
	LastName                string         `db:"last_name" validate:"required"`
	Email                   string         `db:"email" validate:"required,email"`
	Password                string         `db:"password" validate:"required"`
	IsActive                bool           `db:"is_active"`
	BadUser                 bool           `db:"bad_user"`
	BadUserReason           string         `db:"bad_user_reason"`
	PasswordResetToken      *string        `db:"password_reset_token"`
	OrganisationInviteToken *string        `db:"org_invite_token"`
	OrganisationID          *string        `db:"organisation_id"`
	Roles                   []*RoleDBModel `db:"-"`
}

type UserRegistration struct {
	FirstName       string `json:"firstName" validate:"required,first_or_last_name"`
	LastName        string `json:"lastName" validate:"required,first_or_last_name"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,validate_password,eqfield=ConfirmPassword"`
	ConfirmPassword string `json:"confirmPassword" validate:"required"`
	TermsAccepted   bool   `json:"termsAccepted,default:false" validate:"required"`
}

type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
