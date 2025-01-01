package config

import "time"

const (
	CacheDBConfigSettings      = "DBConfigSettings"
	DBMaxIdleConnectionsName   = "DBMaxIdleConnections"
	DBMaxIdleConnectionsValue  = 10
	DBMaxOpenConnectionsString = "DBMaxOpenConnections"
	DBMaxOpenConnectionsValue  = 100
	ConnMaxLifetimeValue       = time.Second * 90
	DBHealthCheckInterval      = time.Second * 5
	WhereOrganisationID        = "organisation_id = ?"
	WhereID                    = "id = ?"
	DBInitialisationFailed     = "database initialisation failed: %s"
)
