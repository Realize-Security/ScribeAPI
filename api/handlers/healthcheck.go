package handlers

import (
	"github.com/gin-gonic/gin"
)

func ApiHealthCheckRoutes(r *gin.RouterGroup) {
	healthcheck := r.Group("/api")
	{
		healthcheck.GET("/", apiHealthCheck)
		healthcheck.GET("/api/health", apiHealthCheck)
	}
}

func apiHealthCheck(c *gin.Context) {
	c.Writer.WriteString("ok")
}
