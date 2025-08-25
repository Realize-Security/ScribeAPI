package router

import (
	"Scribe/handlers/handler"
	"Scribe/pkg/authentication"
	"Scribe/pkg/config"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Router struct {
	userHandler           *handler.UserHandler
	authenticationService *authentication.AuthenticationService
	authorisationService  *authentication.AuthorisationService
}

func NewRouter(
	userHandler *handler.UserHandler,
	authenticationService *authentication.AuthenticationService,
	authorisationService *authentication.AuthorisationService,
) *Router {
	return &Router{
		userHandler:           userHandler,
		authenticationService: authenticationService,
		authorisationService:  authorisationService,
	}
}

func (r *Router) Setup() *gin.Engine {
	router := gin.Default()

	if err := router.SetTrustedProxies(nil); err != nil {
		log.Printf("failed to set trusted proxies: %s", err)
		os.Exit(config.ExitCantCreate)
	}

	r.configureCORS(router)
	r.setupRoutes(router)

	return router
}

func (r *Router) configureCORS(router *gin.Engine) {
	if os.Getenv("DEPLOYMENT") == "production" {
		corsConfig := cors.Config{
			AllowOrigins: []string{
				"https://scribe-dev.realizesec.com",
				"https://scribe-stage.realizesec.com",
				"https://scribe.realizesec.com",
			},
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Cookie"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			MaxAge:           12 * 60 * 60,
		}
		router.Use(cors.New(corsConfig))
	} else {
		router.Use(cors.Default())
	}
}

func (r *Router) setupRoutes(router *gin.Engine) {
	api := router.Group("/api")
	r.setupHealthCheckRoutes(api)
	r.setupPublicRoutes(api)
	r.setupProtectedRoutes(api)
}

func (r *Router) setupHealthCheckRoutes(api *gin.RouterGroup) {
	api.GET("/", handler.HealthCheck)
	api.GET("/healthcheck", handler.HealthCheck)
}

func (r *Router) setupPublicRoutes(api *gin.RouterGroup) {
	public := api.Group("")
	{
		public.POST("/register", r.userHandler.Register)
		public.POST("/login", r.userHandler.Login)
	}
}

// setupProtectedRoutes are rotected routes with authentication middleware
func (r *Router) setupProtectedRoutes(api *gin.RouterGroup) {
	protected := api.Group("")
	protected.Use(r.authenticationService.IsAuthenticated())
	{
		protected.POST("/logout", r.userHandler.Logout)
	}
}
