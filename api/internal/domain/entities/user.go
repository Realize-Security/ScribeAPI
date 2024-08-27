package entities

import (
	"errors"
	"gorm.io/gorm"
)

// UserDBModel contains the common fields for all user
type UserDBModel struct {
	Base
	FirstName               string              `gorm:"column:first_name;type:varchar(255);not null"`
	LastName                string              `gorm:"column:last_name;type:varchar(255);not null"`
	Email                   string              `gorm:"column:email;type:varchar(255);unique;not null"`
	Password                string              `gorm:"column:password;not null"`
	IsActive                bool                `gorm:"column:is_active;default:true"`
	BadUser                 bool                `gorm:"column:bad_user;default:false"`
	BadUserReason           string              `gorm:"column:bad_user_reason;varchar(500);default:''"`
	LoginLocked             bool                `gorm:"column:login_locked;default:false"`
	EmailValidated          bool                `gorm:"column:email_validated;default:false"`
	PasswordResetToken      string              `gorm:"column:password_reset_token;type:varchar(255);unique;default:uuid_generate_v4()"`
	OrganisationInviteToken string              `gorm:"column:org_invite_token;type:varchar(255);unique;default:uuid_generate_v4()"`
	OrganisationID          string              `gorm:"column:organisation_id;type:varchar(255);default:NULL"`
	Organisation            OrganisationDBModel `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;default:NULL"`
	Roles                   []RoleDBModel       `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
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
