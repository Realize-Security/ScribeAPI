package config

import "time"

const (
	DBMaxIdleConnectionsValue = 10
	DBMaxOpenConnectionsValue = 100
	ConnMaxLifetimeValue      = time.Second * 90
	DBHealthCheckInterval     = time.Second * 5
	DBInitialisationFailed    = "database initialisation failed: %s"
)
