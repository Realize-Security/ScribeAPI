package entities

import "github.com/lib/pq"

// OrganisationDBModel is the primary struct type for organisations
type OrganisationDBModel struct {
	Base
	Name                  string         `gorm:"column:name;type:varchar(255);unique;default:not null" json:"name" binding:"required"`
	PrimaryContactName    string         `gorm:"column:primary_contact_name;type:varchar(255);unique;default:not null" json:"primaryContactName" binding:"required"`
	PrimaryContactEmail   string         `gorm:"column:primary_contact_email;type:varchar(255);unique;default:not null" json:"primaryContactEmail" binding:"required"`
	PrimaryContactPhone   string         `gorm:"column:primary_contact_phone;type:varchar(255);unique;default:not null" json:"primaryContactPhone" binding:"required"`
	SecondaryContactName  string         `gorm:"column:secondary_contact_name;type:varchar(255);unique;default:NULL" json:"secondaryContactName"`
	SecondaryContactEmail string         `gorm:"column:secondary_contact_email;type:varchar(255);unique;default:NULL" json:"secondaryContactEmail"`
	SecondaryContactPhone string         `gorm:"column:secondary_contact_phone;type:varchar(255);unique;default:NULL" json:"secondaryContactPhone"`
	PrimaryDomain         string         `gorm:"column:primary_domain;type:varchar(255);unique;default:not null" json:"primaryDomain" binding:"required"`
	AllowedDomains        pq.StringArray `gorm:"column:allowed_domains;type:text[];default:NULL" json:"allowedDomains" binding:"required"`
	MFAEnabled            bool           `gorm:"column:mfa_enabled;not null;default:true" json:"mfaEnabled" binding:"required"`
	IsValidated           bool           `gorm:"column:is_validated;not null;default:false"`
	IsMaster              bool           `gorm:"column:is_master;not null;default:false"`
}
