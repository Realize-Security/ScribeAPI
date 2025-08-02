package main

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
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
	if err := tx.Find(&existingPerms).Error; err != nil {
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

			perm := entities.PermissionDBModel{
				PermissionName: permData.PermName,
			}
			if err := tx.Create(&perm).Error; err != nil {
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
		err := tx.Where("role_name = ?", roleData.RoleName).First(&role).Error
		if err == gorm.ErrRecordNotFound {
			role = entities.RoleDBModel{
				RoleName:    roleData.RoleName,
				Description: roleData.Description,
			}
			if err := tx.Create(&role).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to create role %s: %w", roleData.RoleName, err)
			}
		} else if err != nil {
			tx.Rollback()
			return fmt.Errorf("error checking role %s: %w", roleData.RoleName, err)
		}

		// Update description if changed.
		if role.Description != roleData.Description {
			if err := tx.Model(&role).Update("description", roleData.Description).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to update description for role %s: %w", roleData.RoleName, err)
			}
		}

		// Collect permissions to associate.
		var permsToAdd []*entities.PermissionDBModel
		for _, permData := range roleData.Permissions {
			permsToAdd = append(permsToAdd, createdPerms[permData.PermName])
		}

		// Replace associations to ensure exact match (removes old ones not in list).
		if err := tx.Model(&role).Association("Permissions").Replace(permsToAdd); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to replace permissions for role %s: %w", roleData.RoleName, err)
		}
	}
	return tx.Commit().Error
}
