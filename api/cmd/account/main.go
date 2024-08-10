package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"os"
	"strconv"
)

func main() {
	router := configureRouter()
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
	_ = router.Run(host + ":" + port)
}

func configureRouter() *gin.Engine {
	r := gin.Default()
	return r
}
