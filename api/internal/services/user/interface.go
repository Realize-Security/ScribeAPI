package user

import (
	"Scribe/internal/domain/entities"
	"context"

	"github.com/gin-gonic/gin"
)

type Service interface {
	Register(ctx context.Context, input RegisterInput) (*entities.UserDBModel, error)
	Login(ctx context.Context, email, password string, c *gin.Context) error
	Logout(ctx context.Context, c *gin.Context) error
	GetUser(ctx context.Context, userID int64) (*entities.UserDBModel, error)
}

type RegisterInput struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}
