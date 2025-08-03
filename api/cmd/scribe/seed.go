package main

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"errors"
	"fmt"
	"gorm.io/gorm"
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
}

func seedRolesAndPermissions(db *gorm.DB) error {
	tx := db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	// Preload all existing permissions for efficiency.
	var existingPerms []entities.PermissionDBModel
	if err := tx.Raw("SELECT * FROM permissions WHERE deleted_at IS NULL").Scan(&existingPerms).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to preload permissions: %w", err)
	}
	createdPerms := make(map[string]*entities.PermissionDBModel)
	for i := range existingPerms {
		perm := &existingPerms[i]
		createdPerms[perm.PermissionName] = perm
	}

	// Seed permissions if missing.
	for _, roleData := range defaultRoles {
		for _, permData := range roleData.Permissions {
			if permData.PermName == "" {
				tx.Rollback()
				return fmt.Errorf("empty permission name encountered")
			}
			if _, exists := createdPerms[permData.PermName]; exists {
				continue
			}

			perm := entities.PermissionDBModel{}
			if err := tx.Raw("INSERT INTO permissions (permission_name) VALUES (?) RETURNING *", permData.PermName).Scan(&perm).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to create permission %s: %w", permData.PermName, err)
			}
			createdPerms[permData.PermName] = &perm
		}
	}

	// Seed or update roles and associate permissions.
	for _, roleData := range defaultRoles {
		if roleData.RoleName == "" {
			tx.Rollback()
			return fmt.Errorf("empty role name encountered")
		}

		var role entities.RoleDBModel
		err := tx.Raw("SELECT * FROM roles WHERE role_name = ? AND deleted_at IS NULL LIMIT 1", roleData.RoleName).Scan(&role).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			tx.Rollback()
			return fmt.Errorf("error checking role %s: %w", roleData.RoleName, err)
		}

		if role.ID == 0 { // Assuming ID is uint and 0 means not found
			if err := tx.Raw("INSERT INTO roles (role_name, description) VALUES (?, ?) RETURNING *", roleData.RoleName, roleData.Description).Scan(&role).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to create role %s: %w", roleData.RoleName, err)
			}
		} else {
			// Update description if changed.
			if role.Description != roleData.Description {
				if err := tx.Exec("UPDATE roles SET description = ? WHERE id = ?", roleData.Description, role.ID).Error; err != nil {
					tx.Rollback()
					return fmt.Errorf("failed to update description for role %s: %w", roleData.RoleName, err)
				}
			}
		}

		// Replace associations: first delete existing, then insert new.
		if err := tx.Exec("DELETE FROM role_permissions WHERE role_id = ?", role.ID).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to delete existing permissions for role %s: %w", roleData.RoleName, err)
		}

		for _, permData := range roleData.Permissions {
			permID := createdPerms[permData.PermName].ID
			if err := tx.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", role.ID, permID).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to associate permission %s for role %s: %w", permData.PermName, roleData.RoleName, err)
			}
		}
	}
	return tx.Commit().Error
}
