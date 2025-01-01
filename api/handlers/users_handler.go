package handlers

import (
	"Scribe/internal/services"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	us *services.UserService
}

func NewUserHandler(us *services.UserService) *UserHandler {
	return &UserHandler{
		us: us,
	}
}

func (uh UserHandler) Users(r *gin.RouterGroup) {
	users := r.Group("/api/users")
	{
		users.POST("/register", uh.us.RegisterUser)
	}
}
