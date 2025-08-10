package services

import (
	"Scribe/internal/domain/repositories"

	"github.com/gin-gonic/gin"
)

type OrganisationService struct {
	ur repositories.OrganisationRepository
}

func NewOrganisationServiceRepository(ur repositories.OrganisationRepository) *OrganisationService {
	return &OrganisationService{
		ur: ur,
	}
}

func (os *OrganisationService) Create(c *gin.Context) {

}
