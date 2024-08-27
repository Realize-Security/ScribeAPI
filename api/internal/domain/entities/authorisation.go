package entities

type RoleDBModel struct {
	Base
	RoleName        string              `gorm:"column:role_name;type:varchar(255);unique;not null"  json:"name" binding:"required"`
	Description     string              `gorm:"column:description;type:varchar(255);not null"  json:"description" binding:"required"`
	OrganisationID  string              `gorm:"column:organisation_id;type:varchar(255);default:NULL"`
	Permissions     []PermissionDBModel `gorm:"many2many:role_permissions;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"permissions"`
	GlobalAdminOnly bool                `gorm:"column:global_admin_only;type:boolean;default:false" json:"global_admin_only"`
	Users           []*UserDBModel      `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
}

type PermissionDBModel struct {
	Base
	PermissionName  string `gorm:"column:permission_name;type:varchar(255);unique;default:not null" json:"name" binding:"required"`
	Description     string `gorm:"column:description;type:varchar(255);default:not null"  json:"description" binding:"required"`
	OrganisationID  string `gorm:"column:organisation_id;type:varchar(255);default:NULL"`
	GlobalAdminOnly bool   `gorm:"column:global_admin_only;type:boolean;default:false" json:"global_admin_only"`
}
