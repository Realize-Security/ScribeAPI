package handlers

import (
	"Scribe/internal/services"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	us             *services.UserService
	authentication *services.AuthenticationService
	authorisation  *services.AuthorisationService
}

func NewUserHandler(us *services.UserService, authentication *services.AuthenticationService, authorisation *services.AuthorisationService) *UserHandler {
	return &UserHandler{
		us:             us,
		authentication: authentication,
		authorisation:  authorisation,
	}
}

func (uh UserHandler) Users(r *gin.RouterGroup) {
	unauthenticated := r.Group("/api")
	{
		unauthenticated.POST("/register", uh.us.RegisterUser)
		unauthenticated.POST("/login", uh.us.Login)
	}

	authenticated := r.Group("/api")
	authenticated.Use(uh.authentication.IsAuthenticated())
	{
		unauthenticated.GET("/logout", uh.us.Logout)
	}
}
