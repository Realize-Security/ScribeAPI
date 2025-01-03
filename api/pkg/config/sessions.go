package config

import "time"

const (
	CookieAuthToken                          = "auth_token"
	CookieRefreshToken                       = "refresh_token"
	CookieIsAuthenticated                    = "is_authenticated"
	JTI                                      = "jti"
	HMACSecret                               = "secret"
	LogBadSessionKeyAbort                    = "Insecure session key set. Aborting."
	AuthorizationHeader                      = "Authorization"
	LogAuthHeaderSuccess                     = "authorization header parsed successfully"
	LogAuthHeaderNotFound                    = "authorization header not available"
	LogAuthTokenCreateFailed                 = "error generating token"
	LogAuthTokenValidationFailed             = "token validation failed"
	LogAuthTokenExtractingTokenMetaDataError = "error extracting token metadata"
	LogAuthTokenExtractUserDetailError       = "error extracting jwt user details"
	LogAuthTokenLogoutError                  = "error logging out: %s"
	LogAuthTokenLoggedOut                    = "successfully logged out: %s"
	AuthTokenExpiry                          = time.Minute * 20
	UnspecifiedError                         = "An unknown error occurred"
	CacheSessionPermissionsKey               = "permissions"
	LogLoginSuccess                          = "Successfully logged in: %s"
	LogHashingError                          = "error hashing password"
	LogHashingErrorForUser                   = "error hashing password for: %s"
	LogHashesDontMatch                       = "hashes don't match"
)
