package entities

type RoleDBModel struct {
	Base
	RoleName    string         `gorm:"column:role_name;type:varchar(255);unique;not null"  json:"name" binding:"required"`
	Description string         `gorm:"column:description;type:varchar(255);not null"  json:"description" binding:"required"`
	Users       []*UserDBModel `gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}
