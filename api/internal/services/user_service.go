package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/domain/validators"
	"Scribe/pkg/config"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"log"
	"net/http"
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
		var errs validator.ValidationErrors
		errors.As(err, &errs)
		for _, v := range errs {
			println(v.Error())
		}

		c.JSON(http.StatusBadRequest, gin.H{
			config.ApiError: config.LogUserCreateFailed,
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

func (us *UserService) Login(c *gin.Context) {
	var login entities.UserLogin
	err := c.BindJSON(&login)
	if err != nil {
		log.Printf(err.Error())
		c.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := us.ur.FindByEmail(login.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	if !us.ar.PasswordsMatch(user.Password, login.Password) {
		log.Printf(config.LogHashingErrorForLoginEmail, user.Email)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	token, err := us.ar.GenerateAuthTokenFromUserID(user.ID)
	if err != nil {
		log.Printf(config.LogHashingErrorForUserID, user.ID)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	err = us.ar.LoginUser(token, c)
	if err != nil {
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
	err := us.ar.LogoutUser(c)
	if err != nil {
		c.Writer.WriteHeader(http.StatusInternalServerError)
	} else {
		c.Writer.WriteHeader(http.StatusOK)
	}
}
