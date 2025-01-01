package main

import (
	"Scribe/handlers"
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/domain/validators"
	"Scribe/internal/infrastructure/cache"
	"Scribe/internal/infrastructure/database"
	"Scribe/internal/services"
	"Scribe/pkg/config"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if net.ParseIP(host) == nil {
		_ = fmt.Errorf("error: %s is not a valid IP address. Falling back to: %s", host, "0.0.0.0")
		host = "0.0.0.0"
	}

	if val, err := strconv.Atoi(port); err != nil || (val < 1 || val > 65535) {
		_ = fmt.Errorf("error: %s is not a valid port. Falling back to: %s", port, "8080")
		port = "8080"
	}

	cache.InitCache()
	defer cache.Client.Close()

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
	migrate(database.Db)
	go database.DBHealthMonitor(dbConf)

	validators.Validator = validators.InitValidator()

	router := configureRouter()
	_ = router.Run(host + ":" + port)
}

func configureRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.Default())

	config := cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * 60 * 60, // Maximum age (in seconds) of the preflight request
	}

	r.Use(cors.New(config))

	initialiseHandlers(r)
	return r
}

// initialiseHandlers initialises handlers for routes and types/domains.
func initialiseHandlers(r *gin.Engine) {
	handlers.ApiHealthCheckRoutes(&r.RouterGroup)

	ur := repositories.NewUserRepository(database.Db)
	us := services.NewUserServiceRepository(ur)
	uh := handlers.NewUserHandler(us)

	// Register routes
	uh.Users(&r.RouterGroup)
}

func migrate(db *gorm.DB) {
	log.Println("Migrating database...")
	err := db.AutoMigrate(
		&entities.UserDBModel{},
		//&entities.OrganisationDBModel{},
		//&entities.RoleDBModel{},
		//&entities.PermissionDBModel{}
	)
	if err != nil {
		panic(err.Error())
	}
	log.Println("Database migration succeeded.")
}
