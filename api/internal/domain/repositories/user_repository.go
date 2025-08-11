package repositories

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
)

type UserRepository interface {
	Create(user *entities.UserDBModel) error
	FindByEmail(email string) (*entities.UserDBModel, error)
	FindByID(id int64) (*entities.UserDBModel, error)
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

// Create a new user instance of entities.UserDBModel during registration.
func (ur *userRepository) Create(user *entities.UserDBModel) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	if ur.db == nil {
		return errors.New("database connection not initialized")
	}

	query := `
		INSERT INTO users (first_name, last_name, email, password, is_active, bad_user, bad_user_reason, password_reset_token, org_invite_token)
		VALUES (:first_name, :last_name, :email, :password, :is_active, :bad_user, :bad_user_reason, :password_reset_token, :org_invite_token)`
	_, err := ur.db.NamedExec(query, user)
	if err != nil {
		log.Print(config.LogUserCreateFailed)
		log.Print(err.Error())
		return err
	}

	log.Printf(config.LogUserCreateSuccess, user.UUID)
	return nil
}

// FindByEmail finds a user by their email. Constrained to same organisation as requester.
func (ur *userRepository) FindByEmail(email string) (*entities.UserDBModel, error) {
	ctx := context.Background()
	var user entities.UserDBModel
	query := "SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL LIMIT 1"
	err := ur.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf(config.LogUserFindByEmailFailed, email)
			return nil, errors.New("user not found")
		}
		log.Printf(config.LogUserFindByEmailFailed, email)
		return nil, err
	}

	log.Printf(config.LogUserFindByEmailSuccess, email)
	return &user, nil
}

// FindByID finds a user by their entities.UserDBModel.ID. Constrained to same organisation as requester.
func (ur *userRepository) FindByID(id int64) (*entities.UserDBModel, error) {
	ctx := context.Background()
	var user entities.UserDBModel
	query := "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1"
	err := ur.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf(config.LogUserFindByIDFailed, id)
			return nil, errors.New("user not found")
		}
		log.Printf(config.LogUserFindByIDFailed, id)
		return nil, err
	}

	log.Printf(config.LogUserFindByIDSuccess, id)
	return &user, nil
}

func (ur *userRepository) fetchRolesForUser(userID int64) ([]*entities.RoleDBModel, error) {
	var roles []*entities.RoleDBModel
	query := `
        SELECT r.* 
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = $1 AND r.deleted_at IS NULL
    `
	err := ur.db.Select(&roles, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roles for user ID %d: %w", userID, err)
	}

	for _, role := range roles {
		perms, err := ur.fetchPermissionsForRole(role.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = perms
	}

	return roles, nil
}

func (ur *userRepository) fetchPermissionsForRole(roleID int64) ([]*entities.PermissionDBModel, error) {
	var perms []*entities.PermissionDBModel
	query := `
        SELECT p.* 
        FROM permissions p
        JOIN role_permissions rp ON rp.permission_id = p.id
        WHERE rp.role_id = $1 AND p.deleted_at IS NULL
    `
	err := ur.db.Select(&perms, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permissions for role ID %d: %w", roleID, err)
	}
	return perms, nil
}
