package entities

import "time"

type RoleDBModel struct {
	ID          int                  `db:"id"`
	UUID        string               `db:"uuid"`
	CreatedAt   time.Time            `db:"created_at"`
	UpdatedAt   time.Time            `db:"updated_at"`
	DeletedAt   *time.Time           `db:"deleted_at"`
	RoleName    string               `db:"role_name" validate:"required"`
	Description string               `db:"description" validate:"required"`
	Permissions []*PermissionDBModel `db:"-"`
}

type PermissionDBModel struct {
	ID             int        `db:"id"`
	UUID           string     `db:"uuid"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
	DeletedAt      *time.Time `db:"deleted_at"`
	PermissionName string     `db:"permission_name" validate:"required"`
}
