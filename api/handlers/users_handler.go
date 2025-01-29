package handlers

import (
	"Scribe/internal/services"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	us   *services.UserService
	auth *services.AuthenticationService
}

func NewUserHandler(us *services.UserService, auth *services.AuthenticationService) *UserHandler {
	return &UserHandler{
		us:   us,
		auth: auth,
	}
}

func (uh UserHandler) Users(r *gin.RouterGroup) {
	users := r.Group("/api/users")
	{
		users.POST("/register", uh.us.RegisterUser)
		users.POST("/login", uh.us.Login)
		users.GET("/logout", uh.us.Logout)
	}
}
