package entities

// OrganisationDomainDBModel contains domains associated with a given organisation.
// These can be both allow listed and deny listed domains.
type OrganisationDomainDBModel struct {
	Base
	Domain         string `db:"domain" json:"domain" binding:"required" validate:"required"`
	IsValidated    bool   `db:"is_validated"`
	AllowList      bool   `db:"allow_list"`
	OrganisationID *int   `db:"organisation_id"`
}
