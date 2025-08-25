package handler

import (
	"Scribe/handlers/http/dto/request"
	"Scribe/handlers/http/dto/response"
	"Scribe/internal/services/user"
	"Scribe/pkg/config"
	"Scribe/pkg/validators"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService user.Service
}

func NewUserHandler(userService user.Service) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// Register handles HTTP request and response for user registration
func (h *UserHandler) Register(c *gin.Context) {
	var req request.UserRegistration

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf(config.LogInvalidJsonError, "registration", err)
		c.JSON(http.StatusBadRequest, gin.H{
			config.ApiError: config.MessageInvalidJsonError,
		})
		return
	}

	req.CleanWhiteSpace()

	if validationErrors := validators.ValidateStruct(&req); len(validationErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			config.ValidationError: validationErrors,
		})
		return
	}

	input := user.RegisterInput{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  req.Password,
	}

	createdUser, err := h.userService.Register(c.Request.Context(), input)
	if err != nil {
		log.Printf("Failed to create user in 'registration': %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.LogUserCreateFailed,
		})
		return
	}

	c.JSON(http.StatusCreated, response.UserResponse{
		ID:        createdUser.ID,
		FirstName: createdUser.FirstName,
		LastName:  createdUser.LastName,
		Email:     createdUser.Email,
	})
}

// Login handles HTTP request and response for user login
func (h *UserHandler) Login(c *gin.Context) {
	var req request.UserLogin

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf(config.LogInvalidJsonError, "login", err)
		c.JSON(http.StatusBadRequest, gin.H{
			config.ApiError: config.MessageInvalidJsonError,
		})
		return
	}

	if validationErrors := validators.ValidateStruct(&req); len(validationErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			config.ValidationError: validationErrors,
		})
		return
	}

	// Call service - it returns AuthSet and handles cookie setting internally
	err := h.userService.Login(c.Request.Context(), req.Email, req.Password, c)
	if err != nil {
		log.Printf("Login failed for email %s: %v", req.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{
			config.ApiError: config.MessageInvalidCredentialsError,
		})
		return
	}

	c.Status(http.StatusOK)
}

// Logout handles HTTP request and response for users logging out
func (h *UserHandler) Logout(c *gin.Context) {
	// The authentication service validates the token from cookies and handles the logout logic
	err := h.userService.Logout(c.Request.Context(), c)
	if err != nil {
		log.Printf(config.LogInvalidJsonError, "logout", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			config.ApiError: config.MessageUserLogOutFailed,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		config.ApiMessage: config.MessageUserLoggedOutSuccessfully,
	})
}
