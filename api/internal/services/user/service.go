package user

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/pkg/authentication"
	"Scribe/pkg/config"
	"context"
	"errors"
	"log"

	"github.com/gin-gonic/gin"
)

type service struct {
	userRepo repositories.UserRepository
	authRepo authentication.AuthenticationRepository
}

// NewService creates a new user service that implements the Service interface
func NewService(
	userRepo repositories.UserRepository,
	authRepo authentication.AuthenticationRepository,
) Service {
	return &service{
		userRepo: userRepo,
		authRepo: authRepo,
	}
}

// Register creates a new user account
func (s *service) Register(ctx context.Context, input RegisterInput) (*entities.UserDBModel, error) {
	existingUser, _ := s.userRepo.FindByEmail(input.Email)
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	hashedPassword, err := s.authRepo.HashPassword(input.Password)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return nil, errors.New("failed to process password")
	}

	// Create user entity
	user := &entities.UserDBModel{
		FirstName:     input.FirstName,
		LastName:      input.LastName,
		Email:         input.Email,
		Password:      hashedPassword,
		IsActive:      true,
		TermsAccepted: true,
	}

	// Save to database
	if err := s.userRepo.Create(user); err != nil {
		log.Printf("Failed to create user in database: %v", err)
		return nil, errors.New("failed to create user")
	}

	log.Printf("User created successfully: %s", user.Email)
	return user, nil
}

// Login authenticates a user and sets authentication cookies
func (s *service) Login(ctx context.Context, email, password string, c *gin.Context) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		log.Printf(config.LogUserEmailSearchError, email, err)
		return errors.New("invalid credentials")
	}

	if !s.authRepo.PasswordsMatch(user.Password, password) {
		log.Printf(config.LogHashingErrorForUser, user.UUID)
		return errors.New("invalid credentials")
	}

	log.Printf(config.LogHashingSuccessForUser, user.UUID)

	authSet, err := s.authRepo.GenerateAuthTokenFromUser(user)
	if err != nil {
		log.Printf("Failed to generate auth tokens for user %s: %v", user.UUID, err)
		return errors.New("failed to generate authentication tokens")
	}

	// Use the authentication service's Login method to set cookies
	err = s.authRepo.Login(authSet, c)
	if err != nil {
		log.Printf(config.LogLoginFailed, user.UUID, err)
		return errors.New("failed to complete login")
	}

	log.Printf(config.LogLoginSuccess, user.UUID)
	return nil
}

// Logout terminates a user session by unsetting cookies and updating cache
// Use the authentication service's Logout method
// It will handle token validation, cookie invalidation, and cache cleanup
func (s *service) Logout(ctx context.Context, c *gin.Context) error {
	return s.authRepo.Logout(c)
}

// GetUser retrieves a user by ID
func (s *service) GetUser(ctx context.Context, userID int64) (*entities.UserDBModel, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}
