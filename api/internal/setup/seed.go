package setup

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// RoleData defines types for clarity.
type RoleData struct {
	RoleName    string
	Description string
	Permissions []PermData
}

type PermData struct {
	PermName string
}

// Roles use camelcase names, permissions use snake_case.
var defaultRoles = []RoleData{
	{
		RoleName:    "ClientRootAdministrator",
		Description: "Root account with full administrative access.",
		Permissions: []PermData{
			// Projects
			{config.ProjectCreate}, {config.ProjectList}, {config.ProjectRead},
			{config.ProjectUpdate}, {config.ProjectDelete},
			// Users
			{config.UserCreate}, {config.UserUpdate}, {config.UserList},
			{config.UserRead}, {config.UserDelete}, {config.UserToggleEnabled},
			// Organisations
			{config.OrganisationCreate}, {config.OrganisationUpdate}, {config.OrganisationList},
			{config.OrganisationRead}, {config.OrganisationDelete},
		},
	},
	{
		RoleName:    "ClientUserAdministrator",
		Description: "Users with this role may administer other users within their organisation.",
		Permissions: []PermData{
			// Users
			{config.UserCreate}, {config.UserUpdate}, {config.UserList},
			{config.UserRead}, {config.UserDelete}, {config.UserToggleEnabled},
		},
	},
	{
		RoleName:    "ClientProjectAdministrator",
		Description: "Users with this role may administer projects within their organisation.",
		Permissions: []PermData{
			// Projects
			{config.ProjectCreate}, {config.ProjectList}, {config.ProjectRead},
			{config.ProjectUpdate}, {config.ProjectDelete},
		},
	},
	{
		RoleName:    "ClientOrganisationAdministrator",
		Description: "Users with this role may administer organisations to which they belong.",
		Permissions: []PermData{
			// Organisations
			{config.OrganisationCreate}, {config.OrganisationUpdate}, {config.OrganisationList},
			{config.OrganisationRead}, {config.OrganisationDelete},
		},
	},
}

func SeedRolesAndPermissions(db *sqlx.DB) error {
	ctx := context.Background()
	tx, err := db.Beginx() // Start transaction
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	// Preload existing permissions
	var existingPerms []entities.PermissionDBModel
	err = tx.SelectContext(ctx, &existingPerms, "SELECT * FROM permissions WHERE deleted_at IS NULL")
	if err != nil {
		return fmt.Errorf("failed to preload permissions: %w", err)
	}
	createdPerms := make(map[string]*entities.PermissionDBModel)
	for i := range existingPerms {
		perm := &existingPerms[i]
		createdPerms[perm.PermissionName] = perm
	}

	// Seed permissions if missing
	for _, roleData := range defaultRoles {
		for _, permData := range roleData.Permissions {
			if permData.PermName == "" {
				return fmt.Errorf("empty permission name encountered")
			}
			if _, exists := createdPerms[permData.PermName]; exists {
				continue
			}

			var perm entities.PermissionDBModel
			err = tx.QueryRowxContext(ctx, "INSERT INTO permissions (permission_name, default_permission) VALUES ($1, $2) RETURNING *", permData.PermName, true).StructScan(&perm)
			if err != nil {
				return fmt.Errorf("failed to create permission %s: %w", permData.PermName, err)
			}
			createdPerms[perm.PermissionName] = &perm
		}
	}

	// Seed or update roles and associate permissions
	for _, roleData := range defaultRoles {
		if roleData.RoleName == "" {
			return fmt.Errorf("empty role name encountered")
		}

		var role entities.RoleDBModel
		err = tx.QueryRowxContext(ctx, "SELECT * FROM roles WHERE role_name = $1 AND deleted_at IS NULL LIMIT 1", roleData.RoleName).StructScan(&role)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Create new
				newUUID := uuid.New().String()
				err = tx.QueryRowxContext(ctx, "INSERT INTO roles (uuid, role_name, description, default_role) VALUES ($1, $2, $3, $4) RETURNING *", newUUID, roleData.RoleName, roleData.Description, true).StructScan(&role)
				if err != nil {
					return fmt.Errorf("failed to create role %s: %w", roleData.RoleName, err)
				}
			} else {
				return fmt.Errorf("error checking role %s: %w", roleData.RoleName, err)
			}
		} else {
			// Update description if changed
			if role.Description != roleData.Description {
				_, err = tx.ExecContext(ctx, "UPDATE roles SET description = $1 WHERE id = $2", roleData.Description, role.ID)
				if err != nil {
					return fmt.Errorf("failed to update description for role %s: %w", roleData.RoleName, err)
				}
			}
		}

		// Replace associations: delete existing, then insert new
		_, err = tx.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id = $1", role.ID)
		if err != nil {
			return fmt.Errorf("failed to delete existing permissions for role %s: %w", roleData.RoleName, err)
		}

		for _, permData := range roleData.Permissions {
			permID := createdPerms[permData.PermName].ID
			_, err = tx.ExecContext(ctx, "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)", role.ID, permID)
			if err != nil {
				return fmt.Errorf("failed to associate permission %s for role %s: %w", permData.PermName, roleData.RoleName, err)
			}
		}
	}
	return err
}
