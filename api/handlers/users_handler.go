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
	unauthenticated := r.Group("/api")
	{
		unauthenticated.POST("/register", uh.us.RegisterUser)
		unauthenticated.POST("/login", uh.us.Login)
	}

	authenticated := r.Group("/api")
	authenticated.Use(uh.auth.IsAuthenticated())
	{
		unauthenticated.GET("/logout", uh.us.Logout)
	}
}
