package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/domain/validators"
	"Scribe/pkg/config"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserService struct {
	ur repositories.UserRepository
	ar AuthenticationRepository
}

func NewUserServiceRepository(ur repositories.UserRepository, ar AuthenticationRepository) *UserService {
	return &UserService{
		ur: ur,
		ar: ar,
	}
}

// SelfRegistration is used by users to create an account
func (us *UserService) SelfRegistration(c *gin.Context) {
	var newUser entities.UserRegistration
	err := c.BindJSON(&newUser)
	if err != nil {
		log.Printf(err.Error())
		c.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	newUser.Sanitize()

	validationErrors := validators.ValidateStruct(&newUser)
	if len(validationErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			config.ValidationError: validationErrors,
		})
		return
	}

	hashed, err := us.ar.HashPassword(newUser.ConfirmPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
		return
	}

	user := entities.UserDBModel{
		FirstName:     newUser.FirstName,
		LastName:      newUser.LastName,
		Email:         newUser.Email,
		Password:      hashed,
		IsActive:      true,
		TermsAccepted: true,
	}

	if e := us.ur.Create(&user); e != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
	} else {
		c.Status(http.StatusCreated)
	}
	return
}

func (us *UserService) Login(c *gin.Context) {
	var login entities.UserLogin
	err := c.BindJSON(&login)
	if err != nil {
		log.Printf(err.Error())
		c.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	validationErrors := validators.ValidateStruct(&login)
	if len(validationErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			config.ValidationError: validationErrors,
		})
		return
	}

	user, err := us.ur.FindByEmail(login.Email)
	if err != nil {
		log.Printf(config.LogUserEmailSearchError, login.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	if !us.ar.PasswordsMatch(user.Password, login.Password) {
		log.Printf(config.LogHashingErrorForUser, user.UUID)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	} else {
		log.Printf(config.LogHashingSuccessForUser, user.UUID)
	}

	token, err := us.ar.GenerateAuthTokenFromUserID(user.ID)
	if err != nil {
		log.Printf(config.LogHashingErrorForUser, user.UUID)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	err = us.ar.Login(token, c)
	if err != nil {
		log.Printf(config.LogLoginFailed, user.UUID, err)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	} else {
		log.Printf(config.LogLoginSuccess, user.UUID)
		c.Writer.WriteHeader(http.StatusOK)
		return
	}
}

func (us *UserService) Logout(c *gin.Context) {
	err := us.ar.Logout(c)
	if err != nil {
		c.Writer.WriteHeader(http.StatusInternalServerError)
	} else {
		c.Writer.WriteHeader(http.StatusOK)
	}
}
