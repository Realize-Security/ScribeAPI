package main

import (
	"Scribe/handlers/handler"
	"Scribe/handlers/http/router"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/infrastructure/persistence/cache"
	"Scribe/internal/infrastructure/persistence/database"
	"Scribe/internal/services/user"
	"Scribe/internal/setup"
	"Scribe/pkg/authentication"
	"Scribe/pkg/config"
	"Scribe/pkg/validators"
	"log"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	if err := initDatabase(); err != nil {
		log.Fatal(err)
	}

	initCache()
	validators.Validator = validators.InitValidator()
	deps := setupDependencies()

	r := deps.router.Setup()
	if err := r.Run("0.0.0.0:8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func initDatabase() error {
	dbConf := database.Config{
		MaxIdle:             config.DBMaxIdleConnectionsValue,
		MaxOpen:             config.DBMaxOpenConnectionsValue,
		ConnMaxLifetime:     config.ConnMaxLifetimeValue,
		HealthCheckInterval: config.DBHealthCheckInterval,
	}

	if err := database.ConnectDB(dbConf); err != nil {
		return err
	}

	database.MigrateDb(database.Db)
	go database.DBHealthMonitor(dbConf)

	if err := setup.SeedRolesAndPermissions(database.Db); err != nil {
		return err
	}

	return nil
}

func initCache() {
	cache.SessionCache.Get()
	cache.PermissionIDCache.Get()
}

type Dependencies struct {
	router *router.Router
}

func setupDependencies() Dependencies {
	userRepository := repositories.NewUserRepository(database.Db)
	authenticationService, err := authentication.NewAuthenticationService(userRepository)
	if err != nil {
		log.Fatal("Failed to initialize authentication service:", err)
	}

	authorisationService, err := authentication.NewAuthorisationService(userRepository)
	if err != nil {
		log.Fatal("Failed to initialize authorisation service:", err)
	}

	if err := authorisationService.CachePermissionIDs(); err != nil {
		log.Fatal("Error caching permissions:", err)
	}

	userService := user.NewService(userRepository, authenticationService)
	userHandler := handler.NewUserHandler(userService)

	r := router.NewRouter(
		userHandler,
		authenticationService,
		authorisationService,
	)

	return Dependencies{
		router: r,
	}
}
