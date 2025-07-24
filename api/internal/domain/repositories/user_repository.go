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
	FindByEmail(email string) (*entities.UserDBModel, error)
	FindByID(id int) (*entities.UserDBModel, error)
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

func (ur userRepository) FindByEmail(email string) (*entities.UserDBModel, error) {
	var user entities.UserDBModel
	result := ur.db.Raw("SELECT * FROM users WHERE users.email = @email  AND users.deleted_at IS NULL LIMIT 1",
		map[string]interface{}{
			"email": email,
		}).Scan(&user)

	if result.Error != nil || result.RowsAffected == 0 {
		log.Printf(config.LogUserFindByEmailFailed, email)
		return nil, errors.New("user not found")
	}

	log.Printf(config.LogUserFindByEmailSuccess, email)
	return &user, nil
}

func (ur userRepository) FindByID(id int) (*entities.UserDBModel, error) {
	var user entities.UserDBModel
	result := ur.db.Raw("SELECT * FROM users WHERE users.id = @id  AND users.deleted_at IS NULL LIMIT 1",
		map[string]interface{}{
			"id": id,
		}).Scan(&user)

	if result.Error != nil || result.RowsAffected == 0 {
		log.Printf(config.LogUserFindByIDFailed, id)
		return nil, errors.New("user not found")
	}

	log.Printf(config.LogUserFindByIDSuccess, id)
	return &user, nil
}
