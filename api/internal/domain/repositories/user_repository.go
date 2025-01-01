package repositories

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"errors"
	"gorm.io/gorm"
	"log"
)

type UserRepository interface {
	Create(user *entities.UserDBModel) error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (ur userRepository) Create(user *entities.UserDBModel) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	if ur.db == nil {
		return errors.New("database connection not initialized")
	}

	if result := ur.db.Omit("OrganisationID").Create(user); result.Error != nil {
		log.Print(config.LogUserCreateFailed)
		log.Print(result.Error.Error())
		return result.Error
	}

	log.Printf(config.LogUserCreateSuccess, user.UUID)
	return nil
}
