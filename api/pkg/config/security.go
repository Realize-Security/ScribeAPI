package config

import "time"

var RefreshSecret = "default"

const (
	LogUnauthorisedAccessAttempt = "unauthorised access attempt: %s"
	MinPasswordLength            = 16
	RefreshTokenExpiry           = time.Minute * 60
)
