package entities

// ExpenseDomainDBModel contains the model for expenses incurred by an organisation.
type ExpenseDomainDBModel struct {
	Base
	Name         string              `gorm:"column:domain;type:varchar(255);default:not null" json:"name" binding:"required"`
	Description  string              `gorm:"column:description;type:varchar(255);default:not null" json:"description" binding:"required"`
	Amount       string              `gorm:"column:amount;type:varchar(10);default:0" json:"amount" binding:"required"`
	Currency     string              `gorm:"column:currency;type:varchar(10);default:GBP" json:"currency" binding:"required"`
	ExchangeRate string              `gorm:"column:exchange_rate;type:varchar(10);default:0" json:"exchange_rate" binding:"required"`
	VatApplies   bool                `gorm:"column:vat_applies;type:boolean;default:false" json:"vat_applies"`
	VatPercent   string              `gorm:"column:vat_percent;type:boolean;default:not null" json:"vat_percent"`
	InvoiceLink  string              `gorm:"column:invoice_link;type:boolean;default:not null" json:"invoice_link"`
	Organisation OrganisationDBModel `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;default:not null"`
}
