package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/domain/repositories"
	"Scribe/internal/infrastructure/cache"
	"Scribe/pkg/config"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type AuthenticationRepository interface {
	IsAuthenticated() gin.HandlerFunc
	PasswordsMatch(hashed, plain string) bool
	HashPassword(pwd string) (string, error)
	GenerateAuthTokenFromUser(user *entities.UserDBModel) (*entities.AuthSet, error)
	GenerateAuthTokenFromUserID(userID int) (*entities.AuthSet, error)
	LoginUser(token *entities.AuthSet, c *gin.Context) error
	LogoutUser(c *gin.Context) error
	TokenClaimsFromRequestAndValidate(c *gin.Context) (entities.JWTCustomClaims, error)
	GenerateRefreshToken(userID int) (string, error)
	ValidateRefreshToken(token string) (int, error)
}

type AuthenticationService struct {
	keys *TokenKeys
	ur   repositories.UserRepository
}

func NewAuthenticationService(ur repositories.UserRepository) (*AuthenticationService, error) {
	certManager, err := NewCertManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate manager: %w", err)
	}

	privateKey, publicKey, refreshSecret := certManager.GetKeys()
	keys := &TokenKeys{
		authPrivateKey: privateKey,
		authPublicKey:  publicKey,
		refreshSecret:  refreshSecret,
	}

	return &AuthenticationService{
		keys: keys,
		ur:   ur,
	}, nil
}

type SessionTokenGenerator struct {
	mu sync.Mutex
}

type TokenKeys struct {
	authPrivateKey *rsa.PrivateKey
	authPublicKey  *rsa.PublicKey
	refreshSecret  []byte
}

// IsAuthenticated validates a user session
func (auth *AuthenticationService) IsAuthenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		if valid, err := auth.validateSession(c); err != nil || !valid {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
}

// PasswordsMatch matches submitted password against hashed common value
func (auth *AuthenticationService) PasswordsMatch(hashed, plain string) bool {
	match, err := argon2id.ComparePasswordAndHash(plain, hashed)
	if err != nil {
		log.Println(config.LogHashesDontMatch)
		return false
	}
	return match
}

// HashPassword returns argon2Id hash of submitted plaintext
func (auth *AuthenticationService) HashPassword(pwd string) (string, error) {
	params := &argon2id.Params{
		Memory:      128 * 1024,
		Iterations:  4,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := argon2id.CreateHash(pwd, params)
	if err != nil {
		log.Println(config.LogHashingError)
		return "", err
	}
	return hash, nil
}

// GenerateAuthTokenFromUser creates an authentication token with data extracted from *entities.UserDBModel
func (auth *AuthenticationService) GenerateAuthTokenFromUser(user *entities.UserDBModel) (*entities.AuthSet, error) {
	if user == nil || user.ID < 0 {
		return nil, fmt.Errorf("invalid user for auth troken generation")
	}
	return auth.generateAuthToken(user)
}

// GenerateAuthTokenFromUserID creates an authentication token from an int userID
func (auth *AuthenticationService) GenerateAuthTokenFromUserID(userID int) (*entities.AuthSet, error) {
	if userID < 0 {
		return nil, fmt.Errorf("invalid user ID value: %d", userID)
	}

	user, err := auth.ur.FindByID(userID)
	if err != nil && user != nil {
		return nil, fmt.Errorf("failed to find user with ID %d: %w", userID, err)
	}
	return auth.generateAuthToken(user)
}

// generateAuthToken internal implementation for generating authentication token user int userID
// The generated JTI is associated with the requesting userID in the SessionCache
func (auth *AuthenticationService) generateAuthToken(user *entities.UserDBModel) (*entities.AuthSet, error) {
	if user == nil {
		return nil, fmt.Errorf("invalid user for generateAuthToken")
	}
	generator := new(SessionTokenGenerator)
	jti, err := generator.createJtiSessionValue()
	if err != nil {
		return nil, fmt.Errorf("failed to create session value: %w", err)
	}

	claims := entities.JWTCustomClaims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AuthTokenExpiry)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    config.ApiName,
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["alg"] = "RS256"

	ss, err := token.SignedString(auth.keys.authPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign auth token: %w", err)
	}

	rt, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	state := entities.SessionState{
		JTI: jti,
	}
	updateSessionPermissions(user.Roles, &state)
	addSessionToCache(user.ID, state, config.CacheNoTTLExpiry)

	return &entities.AuthSet{
		AuthToken:    ss,
		RefreshToken: rt,
		JTI:          claims.RegisteredClaims.ID,
	}, nil
}

// addSessionToCache sets the generated JTI as the value for the userID key
func addSessionToCache(userID int, session entities.SessionState, ttl time.Duration) {
	sc := cache.SessionCache.Get()
	sc.Set(userID, session, ttl)
}

// updateSessionPermissions overwrites existing roles in session with roles associated with user.
func updateSessionPermissions(roles []*entities.RoleDBModel, state *entities.SessionState) error {
	if state == nil {
		return fmt.Errorf("session state cannot be nil")
	}

	if len(roles) == 0 {
		state.PermissionIDs = nil
		return nil
	}

	trackedPermissions := make(map[int]struct{})
	var perms []int

	for _, role := range roles {
		if role == nil {
			continue
		}
		for _, perm := range role.Permissions {
			if perm == nil {
				continue
			}
			if _, exists := trackedPermissions[perm.ID]; !exists {
				trackedPermissions[perm.ID] = struct{}{}
				perms = append(perms, perm.ID)
			}
		}
	}
	state.PermissionIDs = perms
	return nil
}

// deleteSessionFromCache deletes the JTI for the associated userID from the SessionCache
func deleteSessionFromCache(userID int) {
	sc := cache.SessionCache.Get()
	sc.Delete(userID)
}

func (auth *AuthenticationService) GenerateRefreshToken(userID int) (string, error) {
	claims := entities.JWTCustomClaims{
		UserID:  userID,
		TokenID: uuid.Must(uuid.NewV4()).String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.ApiName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token.Header["alg"] = "HS512"

	return token.SignedString(auth.keys.refreshSecret)
}

func validateTokenSignature(auth *AuthenticationService, tokenString string) (jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &entities.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return auth.keys.authPublicKey, nil
	})
	if err != nil {
		return jwt.Token{}, fmt.Errorf("failed to validate token: %w", err)
	}

	if !token.Valid {
		return jwt.Token{}, fmt.Errorf("token is invalid")
	}

	return *token, nil
}

func (auth *AuthenticationService) ValidateRefreshToken(tokenString string) (int, error) {
	token, err := jwt.ParseWithClaims(tokenString, &entities.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return auth.keys.refreshSecret, nil
	})

	if err != nil {
		return -1, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	claims, ok := token.Claims.(*entities.JWTCustomClaims)
	if !ok || !token.Valid {
		return -1, fmt.Errorf("invalid refresh token claims")
	}

	if time.Now().After(claims.ExpiresAt.Time) {
		return -1, fmt.Errorf("refresh token has expired")
	}

	return claims.UserID, nil
}

// createJtiSessionValue generates a 32-byte value for use as the 'jti' - RFC 7519
func (stg *SessionTokenGenerator) createJtiSessionValue() (string, error) {
	b := make([]byte, 32)
	stg.mu.Lock()
	defer stg.mu.Unlock()
	_, err := rand.Read(b)
	if err != nil {
		log.Print("unable to generate random value using rand.Read(b) for JTI")
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// extractAuthCookies receives a user request and extracts the auth and refresh tokens from cookies.
func extractAuthCookies(c *gin.Context) (*entities.AuthSet, error) {
	cookies := c.Request.Cookies()
	authSet := &entities.AuthSet{}

	for _, cookie := range cookies {
		switch cookie.Name {
		case config.CookieAuthToken:
			authSet.AuthToken = cookie.Value
		case config.CookieRefreshToken:
			authSet.RefreshToken = cookie.Value
		}
	}

	if authSet.AuthToken == "" && authSet.RefreshToken == "" {
		return nil, errors.New(config.LogExtractAuthCookiesError)
	}
	return authSet, nil
}

// extractClaimsFromToken extracts metadata from a token
func extractClaimsFromToken(token *jwt.Token) (entities.JWTCustomClaims, error) {
	claims, ok := token.Claims.(*entities.JWTCustomClaims)
	if ok && token.Valid {
		return entities.JWTCustomClaims{
			UserID: claims.UserID,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  claims.IssuedAt,
				ExpiresAt: claims.ExpiresAt,
				NotBefore: claims.NotBefore,
				Issuer:    claims.Issuer,
				ID:        claims.ID,
			},
		}, nil
	}
	err := errors.New(config.LogAuthTokenExtractingTokenMetaDataError)
	log.Printf(err.Error())
	return entities.JWTCustomClaims{}, err
}

// TokenClaimsFromRequestAndValidate parses Authorization headers, validates tokens and extracts claims
func (auth *AuthenticationService) TokenClaimsFromRequestAndValidate(c *gin.Context) (entities.JWTCustomClaims, error) {
	e := entities.JWTCustomClaims{}
	authSet, pErr := extractAuthCookies(c)
	if pErr != nil {
		return e, pErr
	}
	token, vErr := validateTokenSignature(auth, authSet.AuthToken)
	if vErr != nil {
		return e, vErr
	}
	claims, err := extractClaimsFromToken(&token)
	if err != nil {
		return e, err
	}
	return claims, nil
}

// validateSession validates session cookies and reissues if auth/refresh values are valid.
func (auth *AuthenticationService) validateSession(c *gin.Context) (bool, error) {
	ac, err := extractAuthCookies(c)
	if err != nil {
		return false, err
	}

	// Extract user ID from auth token (without signature validation)
	parser := jwt.NewParser()
	at, _, err := parser.ParseUnverified(ac.AuthToken, &entities.JWTCustomClaims{})
	if err != nil {
		return false, err
	}

	atClaims, ok := at.Claims.(*entities.JWTCustomClaims)
	if !ok {
		return false, errors.New("failed to parse auth token claims")
	}

	userID := atClaims.UserID

	// Check if user exists in cache (required for all authentication)
	sc := cache.SessionCache.Get()
	_, exists := sc.Get(userID)
	if !exists {
		return false, errors.New("user session not found")
	}

	// Try to validate the auth token first
	_, err = validateTokenSignature(auth, ac.AuthToken)
	if err == nil {
		return true, nil
	}

	// If auth token is invalid AND current user's JTI is in SessionCache, try to validate the refresh token
	userID, err = auth.ValidateRefreshToken(ac.RefreshToken)
	_, exists = sc.Get(userID)

	if err != nil || !exists {
		deleteSessionFromCache(userID)
		return false, err
	}

	// Generate new auth set and reissue cookies
	newAuthSet, err := auth.GenerateAuthTokenFromUserID(userID)
	if err != nil {
		deleteSessionFromCache(userID)
		return false, err
	}

	setLoginCookies(newAuthSet, c, config.CookieDomain, secureCookies())
	return true, nil
}

func (auth *AuthenticationService) LoginUser(token *entities.AuthSet, c *gin.Context) error {
	if token == nil {
		return errors.New("token AuthSet is nil")
	}
	if c == nil {
		return errors.New("gin context is nil")
	}
	setLoginCookies(token, c, config.CookieDomain, secureCookies())
	return nil
}

func setLoginCookies(token *entities.AuthSet, c *gin.Context, domain string, secure bool) {
	setCookieValue(c, config.CookieAuthToken, token.AuthToken, "/", domain, int(config.AuthTokenExpiry.Seconds()), secure, true)
	setCookieValue(c, config.CookieRefreshToken, token.RefreshToken, "/", domain, int(config.RefreshTokenExpiry.Seconds()), secure, true)
	setCookieValue(c, config.UnsafeCookieIsAuthenticated, "true", "/", domain, int(config.RefreshTokenExpiry.Seconds()), secure, false)
}

func (auth *AuthenticationService) LogoutUser(c *gin.Context) error {
	claims, err := auth.TokenClaimsFromRequestAndValidate(c)
	if err != nil {
		log.Printf(config.LogLogoutTokenValidationFailed, err.Error())
		return err
	}

	invalidateCookies(c, config.CookieDomain, secureCookies())
	log.Printf(config.LogLogoutUserSuccess, claims.UserID)

	deleteSessionFromCache(claims.UserID)

	return nil
}

func invalidateCookies(c *gin.Context, domain string, secure bool) {
	setCookieValue(c, config.CookieAuthToken, "", "/", domain, 0, secure, true)
	setCookieValue(c, config.CookieRefreshToken, "", "/", domain, 0, secure, true)
	setCookieValue(c, config.UnsafeCookieIsAuthenticated, "false", "/", domain, 3600, secure, false)
}

func setCookieValue(c *gin.Context, key, value, path, domain string, maxAge int, secure, httpOnly bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     key,
		Value:    value,
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: http.SameSiteStrictMode,
	})
}

func secureCookies() bool {
	if os.Getenv("GO_ENV") == "development" {
		return false
	}
	return true
}
