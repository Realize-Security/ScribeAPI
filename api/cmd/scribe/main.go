package main

import (
	"Scribe/handlers"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/domain/validators"
	"Scribe/internal/infrastructure/cache"
	"Scribe/internal/infrastructure/database"
	"Scribe/internal/services"
	"Scribe/internal/setup"
	"Scribe/pkg/config"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	dbConf := database.Config{
		MaxIdle:             config.DBMaxIdleConnectionsValue,
		MaxOpen:             config.DBMaxOpenConnectionsValue,
		ConnMaxLifetime:     config.ConnMaxLifetimeValue,
		HealthCheckInterval: config.DBHealthCheckInterval,
	}
	err := database.ConnectDB(dbConf)
	if err != nil {
		log.Printf(config.DBInitialisationFailed, err.Error())
		os.Exit(config.ExitBadConnection)
	}
	database.MigrateDb(database.Db)
	go database.DBHealthMonitor(dbConf)

	// Cache initialisation
	cache.SessionCache.Get()
	cache.PermissionIDCache.Get()

	// Seed database
	err = setup.SeedRolesAndPermissions(database.Db) // Updated to sqlx
	if err != nil {
		log.Printf("error seeding database: %v", err)
		os.Exit(config.ExitCantCreate)
	}

	// Validators initialisation
	validators.Validator = validators.InitValidator()

	router := configureRouter()
	_ = router.Run("0.0.0.0:8080")
}

func configureRouter() *gin.Engine {
	r := gin.Default()
	err := r.SetTrustedProxies(nil)
	if err != nil {
		log.Printf("failed to set trusted proxies: %s", err)
		os.Exit(config.ExitCantCreate)
	}

	if isProduction() {
		r.Use(cors.Default())

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

		r.Use(cors.New(corsConfig))
	}

	initialiseHandlers(r)
	return r
}

// initialiseHandlers initialises handlers for routes and types/domains.
func initialiseHandlers(r *gin.Engine) {
	handlers.ApiHealthCheckRoutes(&r.RouterGroup)

	userRepository := repositories.NewUserRepository(database.Db)
	authenticationService, err := services.NewAuthenticationService(userRepository)
	if err != nil {
		log.Printf("failed to initialise authentication service: %s", err.Error())
		os.Exit(config.ExitError)
	}

	authorisationService, err := services.NewAuthorisationService(userRepository)
	if err != nil {
		log.Printf("failed to initialise authorisation service: %s", err.Error())
		os.Exit(config.ExitError)
	}

	// Cache Permissions
	err = authorisationService.CachePermissionIDs()
	if err != nil {
		log.Printf("error caching permissions in main.go: %v", err)
		os.Exit(config.ExitCantCreate)
	}

	userServiceRepository := services.NewUserServiceRepository(userRepository, authenticationService)
	userHandler := handlers.NewUserHandler(userServiceRepository, authenticationService, authorisationService)

	// Register routes
	userHandler.Users(&r.RouterGroup)
}

func isProduction() bool {
	return os.Getenv("DEPLOYMENT") == "production"
}
