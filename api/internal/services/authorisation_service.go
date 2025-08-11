package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/infrastructure/cache"
	"Scribe/internal/infrastructure/database"
	"Scribe/pkg/config"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthorisationRepository interface {
	CreatNewUser() gin.HandlerFunc
}

type AuthorisationService struct {
	ur              repositories.UserRepository
	sessionCache    *cache.Cache[int64, entities.SessionState]
	permissionCache *cache.Cache[string, int64]
}

func NewAuthorisationService(ur repositories.UserRepository) (*AuthorisationService, error) {
	return &AuthorisationService{
		ur:              ur,
		sessionCache:    cache.SessionCache.Get(),
		permissionCache: cache.PermissionIDCache.Get(),
	}, nil
}

// UserHasPermission verifies user has all permissions for user creation
func (auth *AuthorisationService) UserHasPermission(c *gin.Context, requester *entities.UserDBModel, neededPermissions []string) {
	permissionCache := cache.PermissionIDCache.Get()
	if permissionCache.Len() == 0 {
		err := auth.CachePermissionIDs()
		if err != nil {
			log.Print("unable to cache permissions")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	userSession, ok := auth.sessionCache.Get(requester.ID)
	if !ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	needed, err := auth.GetIDsForPermissionStrings(neededPermissions)
	if err != nil {
		log.Printf("error getting permission IDs: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	userPermMap := make(map[int64]bool, len(userSession.PermissionIDs))
	for _, permID := range userSession.PermissionIDs {
		userPermMap[permID] = true
	}

	for _, neededPerm := range needed {
		if !userPermMap[neededPerm] {
			auth.LogFailedAuthorisation(requester, needed, neededPerm)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	return
}

func (auth *AuthorisationService) LogFailedAuthorisation(requester *entities.UserDBModel, needed map[string]int64, failedID int64) {
	for key, value := range needed {
		if value == failedID {
			log.Printf(config.LogUserUnauthorised, requester.ID, key)
			return
		}
	}
	return
}

// CreatNewUser verifies user has all permissions for user creation
func (auth *AuthorisationService) CreatNewUser(requester *entities.UserDBModel) gin.HandlerFunc {
	return func(c *gin.Context) {
		neededPermissions := []string{config.UserList, config.UserCreate, config.UserRead}
		auth.UserHasPermission(c, requester, neededPermissions)
	}
}

func (auth *AuthorisationService) CachePermissionIDs() error {
	ar := repositories.NewAuthorisationRepository(database.Db)
	err := ar.CachePermissionIDs()
	if err != nil {
		log.Printf("error caching permissions: %v", err)
		return err
	}
	return nil
}

func (auth *AuthorisationService) GetIDsForPermissionStrings(names []string) (map[string]int64, error) {
	needed := make(map[string]int64, len(names))
	var missing []string
	permissionCache := cache.PermissionIDCache.Get()
	if permissionCache.Len() == 0 {
		err := auth.CachePermissionIDs()
		if err != nil {
			log.Printf(config.LogUnableToCachePermissions, err)
			return nil, err
		}
	}

	for _, perm := range names {
		id, ok := permissionCache.Get(perm)
		if ok {
			needed[perm] = id
		} else {
			missing = append(missing, perm)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing permission IDs for: %v", missing)
	}
	return needed, nil
}
