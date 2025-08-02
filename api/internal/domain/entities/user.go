package entities

import (
	"errors"
	"gorm.io/gorm"
)

type UserDBModel struct {
	Base
	FirstName               string              `gorm:"column:first_name;type:varchar(255);not null"`
	LastName                string              `gorm:"column:last_name;type:varchar(255);not null"`
	Email                   string              `gorm:"column:email;type:varchar(255);unique;not null"`
	Password                string              `gorm:"column:password;not null"`
	IsActive                bool                `gorm:"column:is_active;default:true"`
	BadUser                 bool                `gorm:"column:bad_user;default:false"`
	BadUserReason           string              `gorm:"column:bad_user_reason;varchar(500);default:''"`
	PasswordResetToken      *string             `gorm:"column:password_reset_token;type:varchar(255);unique"`
	OrganisationInviteToken *string             `gorm:"column:org_invite_token;type:varchar(255);unique"`
	OrganisationID          string              `gorm:"column:organisation_id;type:varchar(255);default:NULL"`
	Organisation            OrganisationDBModel `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;default:NULL"`
	Roles                   []*RoleDBModel      `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (u *UserDBModel) TableName() string {
	return "users"
}

func (u *UserDBModel) BeforeSave(tx *gorm.DB) error {
	if u.BadUser && u.BadUserReason == "" {
		return errors.New("BadUserReason must be provided when BadUser is true")
	}

	if !u.BadUser && u.BadUserReason != "" {
		u.BadUserReason = ""
	}
	return nil
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
