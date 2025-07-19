package config

import "time"

const (
	// CookieAuthToken is the primary authentication token containing the user's JWT
	CookieAuthToken = "auth_token"
	// CookieRefreshToken primary refresh token for ensuring user stays authenticated when JWT expires and refresh token has not
	CookieRefreshToken = "refresh_token"
	// UnsafeCookieIsAuthenticated referenced purely by the user interface to manage rendering of authenticated and unauthenticated views
	// NOT used for man aging access to authenticated server-side data.
	UnsafeCookieIsAuthenticated = "is_authenticated"

	JTI              = "jti"
	AuthKeySecret    = "auth_key_secret"
	RefreshKeySecret = "refresh_key_secret"

	DefaultKeyPath     = "./keys"
	AuthPrivateKeyPath = DefaultKeyPath + "/auth_private.pem"
	AuthPublicKeyPath  = DefaultKeyPath + "/auth_public.pem"
	RefreshKeyPath     = DefaultKeyPath + "/refresh_secret"

	RSAKeySize     = 2048
	RefreshKeySize = 32

	AuthTokenExpiry    = time.Minute * 20
	RefreshTokenExpiry = time.Hour * 24 * 7

	LogBadSessionKeyAbort                    = "Insecure session key set. Aborting."
	LogAuthHeaderSuccess                     = "authorization header parsed successfully"
	LogAuthHeaderNotFound                    = "authorization header not available"
	LogAuthTokenCreateFailed                 = "error generating token"
	LogAuthTokenValidationFailed             = "token validation failed"
	LogAuthTokenExtractingTokenMetaDataError = "error extracting token metadata"
	LogAuthTokenExtractUserDetailError       = "error extracting jwt user details"
	LogAuthTokenLogoutError                  = "error logging out: %s"
	LogAuthTokenLoggedOut                    = "successfully logged out: %s"
	LogKeyGeneration                         = "generating new key pair at: %s"
	LogKeyLoadError                          = "error loading keys: %s"
	LogKeyGenerationError                    = "error generating keys: %s"
	LogKeySaveError                          = "error saving keys: %s"
	UnspecifiedError                         = "An unknown error occurred"
	CacheSessionPermissionsKey               = "permissions"
	LogLoginSuccess                          = "Successfully logged in: %s"
	LogLogoutFailed                          = "failed to logout user: '%d' with error: '%s'"
	LogLogoutTokenValidationFailed           = "failed to validate token for logout: %s"
	LogLogoutUserSuccess                     = "logged out user: %d"
	LogHashingError                          = "error hashing password"
	LogHashingErrorForLoginEmail             = "password mismatch for user identifier: %s"
	LogHashingErrorForUserID                 = "error hashing password for: %d"
	LogHashesDontMatch                       = "hashes don't match"
	LogExtractAuthCookiesError               = "error extracting auth tokens from cookie: %s"
)
