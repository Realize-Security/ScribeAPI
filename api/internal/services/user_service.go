package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/domain/validators"
	"Scribe/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"log"
	"net/http"
)

type UserService struct {
	ur repositories.UserRepository
}

func NewUserServiceRepository(ur repositories.UserRepository) *UserService {
	return &UserService{
		ur: ur,
	}
}

func (us *UserService) RegisterUser(c *gin.Context) {
	var newUser entities.UserRegistration
	err := c.BindJSON(&newUser)
	if err != nil {
		log.Printf(err.Error())
		c.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = validators.Validator.Struct(&newUser)
	if err != nil {
		errs := err.(validator.ValidationErrors)
		for _, v := range errs {
			println(v.Error())
		}

		c.JSON(http.StatusBadRequest, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
		return
	}

	hashed, err := HashPassword(newUser.ConfirmPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
		return
	}

	user := entities.UserDBModel{
		FirstName: newUser.FirstName,
		LastName:  newUser.LastName,
		Email:     newUser.Email,
		Password:  hashed,
	}

	if e := us.ur.Create(&user); e != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
	} else {
		c.JSON(http.StatusCreated, gin.H{
			config.ApiMessage: config.LogUserCreateSuccess,
		})
	}
	return
}
