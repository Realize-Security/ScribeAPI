package entities

import "github.com/lib/pq"

// OrganisationDBModel is the primary struct type for organisations
type OrganisationDBModel struct {
	Base
	Name                  string         `gorm:"column:name;type:varchar(255);unique;default:not null" json:"name" validate:"required"`
	PrimaryContactName    string         `gorm:"column:primary_contact_name;type:varchar(255);unique;default:not null" json:"primaryContactName" validate:"required"`
	PrimaryContactEmail   string         `gorm:"column:primary_contact_email;type:varchar(255);unique;default:not null" json:"primaryContactEmail" validate:"required,email"`
	PrimaryContactPhone   string         `gorm:"column:primary_contact_phone;type:varchar(255);unique;default:not null" json:"primaryContactPhone" validate:"required"`
	SecondaryContactName  string         `gorm:"column:secondary_contact_name;type:varchar(255);unique;default:NULL" json:"secondaryContactName"`
	SecondaryContactEmail string         `gorm:"column:secondary_contact_email;type:varchar(255);unique;default:NULL" json:"secondaryContactEmail" validate:"email"`
	SecondaryContactPhone string         `gorm:"column:secondary_contact_phone;type:varchar(255);unique;default:NULL" json:"secondaryContactPhone"`
	PrimaryDomain         string         `gorm:"column:primary_domain;type:varchar(255);unique;default:not null" json:"primaryDomain" validate:"required"`
	AllowedDomains        pq.StringArray `gorm:"column:allowed_domains;type:text[];default:NULL" json:"allowedDomains" validate:"required"`
	MFAEnabled            bool           `gorm:"column:mfa_enabled;not null;default:true" json:"mfaEnabled" validate:"required"`
	IsValidated           bool           `gorm:"column:is_validated;not null;default:false"`
	IsMaster              bool           `gorm:"column:is_master;not null;default:false"`
}

func (o *OrganisationDBModel) TableName() string {
	return "organisations"
}
