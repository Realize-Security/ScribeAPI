package config

const (
	ApiName                  = "ScribeAPI"
	CookieDomain             = "realizesec.com"
	MasterOrganisation       = "Realize Security"
	MasterDomain             = "realizesec.com"
	MasterUserFirstName      = "Janus"
	MasterUserLastName       = "Admin"
	MasterUserEmail          = "janus-admin@realizesec.com"
	GlobalAdminName          = "GLOBAL_ADMIN"
	MinEntropyBits           = 60
	Logfile                  = "/vol/log/application.log"
	ErrorLog                 = "/vol/log/error.log"
	LogLogfileCreationFailed = "Creating of standard logging file failed"
	ApiMessage               = "message"
	ApiError                 = "error"
	ApiResult                = "result"
	APIInvalidRequestMessage = "Invalid request"
	IDRegex                  = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
)
