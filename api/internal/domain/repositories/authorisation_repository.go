package repositories

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/infrastructure/cache"
	"Scribe/pkg/config"
	"errors"
	"gorm.io/gorm"
	"log"
)

type AuthorisationRepository interface {
	CachePermissionIDs() error
}

type authorisationRepository struct {
	db *gorm.DB
}

func NewAuthorisationRepository(db *gorm.DB) AuthorisationRepository {
	return &authorisationRepository{
		db: db,
	}
}

func (ar authorisationRepository) CachePermissionIDs() error {
	var permissions []entities.PermissionDBModel
	result := ar.db.Raw("SELECT id, permission_name FROM permissions WHERE permissions.deleted_at IS NULL").Scan(&permissions)

	if result.Error != nil || result.RowsAffected == 0 {
		log.Print(config.LogFailedToRetrievePermissions)
		return errors.New(config.LogFailedToRetrievePermissions)
	}

	permissionCache := cache.PermissionIDCache.Get()
	for _, permission := range permissions {
		permissionCache.Set(permission.PermissionName, permission.ID, config.CacheNoTTLExpiry)
	}

	return nil
}
