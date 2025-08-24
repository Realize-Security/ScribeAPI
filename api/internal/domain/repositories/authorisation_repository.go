package repositories

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/infrastructure/persistence/cache"
	"Scribe/pkg/config"
	"context"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
)

type AuthorisationRepository interface {
	CachePermissionIDs() error
}

type authorisationRepository struct {
	db *sqlx.DB
}

func NewAuthorisationRepository(db *sqlx.DB) AuthorisationRepository {
	return &authorisationRepository{
		db: db,
	}
}

func (ar authorisationRepository) CachePermissionIDs() error {
	ctx := context.Background()
	var permissions []entities.PermissionDBModel
	query := "SELECT id, permission_name FROM permissions WHERE deleted_at IS NULL"
	err := ar.db.SelectContext(ctx, &permissions, query)
	if err != nil {
		log.Print(config.LogFailedToRetrievePermissions)
		return fmt.Errorf("%s: %w", config.LogFailedToRetrievePermissions, err)
	}

	permissionCache := cache.PermissionIDCache.Get()
	for _, permission := range permissions {
		permissionCache.Set(permission.PermissionName, permission.ID, config.CacheNoTTLExpiry)
	}
	return nil
}
