package entities

type RoleDBModel struct {
	Base
	RoleName    string               `gorm:"column:role_name;type:varchar(255);unique;not null"`
	Description string               `gorm:"column:description;type:varchar(255);not null"`
	Users       []*UserDBModel       `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Permissions []*PermissionDBModel `gorm:"many2many:role_permissions;joinForeignKey:role_id;joinReferences:permission_id;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type PermissionDBModel struct {
	Base
	PermissionName string         `gorm:"column:permission_name;type:varchar(255);unique;not null"`
	Roles          []*RoleDBModel `gorm:"many2many:role_permissions;joinForeignKey:permission_id;joinReferences:role_id;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (RoleDBModel) TableName() string {
	return "roles"
}

func (PermissionDBModel) TableName() string {
	return "permissions"
}
