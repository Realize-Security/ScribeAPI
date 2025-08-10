package repositories

import (
	"github.com/jmoiron/sqlx"
)

type OrganisationRepository interface {
}

type organisationRepository struct {
	db *sqlx.DB
}

func NewOrganisationRepository(db *sqlx.DB) OrganisationRepository {
	return &organisationRepository{
		db: db,
	}
}
