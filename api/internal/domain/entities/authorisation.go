package entities

type RoleDBModel struct {
	Base
	RoleName    string               `db:"role_name" validate:"required"`
	Description string               `db:"description" validate:"required"`
	Permissions []*PermissionDBModel `db:"-"`
}

type PermissionDBModel struct {
	Base
	PermissionName string `db:"permission_name" validate:"required"`
}
