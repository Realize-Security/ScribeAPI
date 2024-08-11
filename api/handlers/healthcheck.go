package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func ApiHealthCheckRoutes(r *gin.RouterGroup) {
	healthcheck := r.Group("/api")
	{
		healthcheck.Any("/", apiHealthCheck)
		healthcheck.Any("/api/health", apiHealthCheck)
	}
}

func apiHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, nil)
}
