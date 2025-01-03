package entities

// OrganisationDomainDBModel contains domains associated with a given organisation.
// These can be both allow listed and deny listed domains.
type OrganisationDomainDBModel struct {
	Base
	Domain       string              `gorm:"column:domain;type:varchar(255);unique;default:not null" json:"domain" binding:"required"`
	IsValidated  bool                `gorm:"column:is_validated;not null;default:false"`
	AllowList    bool                `gorm:"column:allow_list;not null;default:false"`
	Organisation OrganisationDBModel `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;default:not null"`
}
