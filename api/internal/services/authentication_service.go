package services

import (
	"Scribe/internal/domain/entities"
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
	GenerateAuthToken(userID int) (*entities.AuthSet, error)
	LoginUser(token *entities.AuthSet, c *gin.Context) error
	LogoutUser(c *gin.Context) error
	TokenClaimsFromRequestAndValidate(c *gin.Context) (entities.JWTCustomClaims, error)
	GetCustomClaims(c *gin.Context) (entities.JWTCustomClaims, error)
	GenerateRefreshToken(userID int) (string, error)
	ValidateRefreshToken(token string) (int, error)
}

type AuthenticationService struct {
	keys *TokenKeys
}

func NewAuthenticationService() (*AuthenticationService, error) {
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
		if valid, err := auth.authCookiesValid(c); err != nil || !valid {
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

func (auth *AuthenticationService) GenerateAuthToken(userID int) (*entities.AuthSet, error) {
	if userID < 0 {
		return nil, fmt.Errorf("invalid user ID value: %d", userID)
	}
	generator := new(SessionTokenGenerator)
	jti, err := generator.createJtiSessionValue()
	if err != nil {
		return nil, fmt.Errorf("failed to create session value: %w", err)
	}

	claims := entities.JWTCustomClaims{
		UserID: userID,
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

	rt, err := auth.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &entities.AuthSet{
		AuthToken:    ss,
		RefreshToken: rt,
		JTI:          claims.RegisteredClaims.ID,
	}, nil
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

	if authSet.AuthToken == "" || authSet.RefreshToken == "" {
		return nil, errors.New(config.LogExtractAuthCookiesError)
	}
	return authSet, nil
}

// extractTokenFromString extracts claims from a token string but does NOT validate the signature
func extractTokenFromString(tokenString string) (jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &entities.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.AuthKeySecret), nil
	})
	if err != nil {
		log.Printf(err.Error())
		return jwt.Token{}, err
	}
	return *token, nil
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

func tokenClaimsFromRequestNoValidate(c *gin.Context) (entities.JWTCustomClaims, error) {
	e := entities.JWTCustomClaims{}
	as, err := extractAuthCookies(c)
	if err != nil {
		return e, err
	}
	t, err := extractTokenFromString(as.AuthToken)
	if err != nil {
		return e, err
	}
	claims, err := extractClaimsFromToken(&t)
	return claims, nil
}

// authCookiesValid validates session cookies and reissues if auth/refresh values are valid.
func (auth *AuthenticationService) authCookiesValid(c *gin.Context) (bool, error) {
	ac, err := extractAuthCookies(c)
	if err != nil {
		return false, err
	}

	// Try to validate the auth token first
	_, err = validateTokenSignature(auth, ac.AuthToken)
	if err == nil {
		return true, nil
	}

	// If auth token is invalid, try to validate the refresh token
	userUUID, err := auth.ValidateRefreshToken(ac.RefreshToken)
	if err != nil {
		return false, err
	}

	// If we got here, the refresh token is valid but the auth token isn't
	// Check that the invalid auth token was for the same user
	parser := jwt.NewParser()
	at, _, err := parser.ParseUnverified(ac.AuthToken, &entities.JWTCustomClaims{})
	if err != nil {
		return false, err
	}

	atClaims, ok := at.Claims.(*entities.JWTCustomClaims)
	if !ok {
		return false, errors.New("failed to parse auth token claims")
	}

	if atClaims.UserID != userUUID {
		errS := fmt.Sprintf(config.LogRefreshAndAuthTokenUIDMismatchAlert, atClaims.UserID, userUUID)
		log.Printf(errS)
		return false, errors.New(errS)
	}

	// Generate new auth set and reissue cookies
	newAuthSet, err := auth.GenerateAuthToken(userUUID)
	if err != nil {
		return false, err
	}

	setLoginCookies(newAuthSet, c, cookieDomain(), secureCookies())
	return true, nil
}

// GetCustomClaims returns entities.JWTCustomClaims from a request context. This does NOT validate the token.
func (auth *AuthenticationService) GetCustomClaims(c *gin.Context) (entities.JWTCustomClaims, error) {
	return tokenClaimsFromRequestNoValidate(c)
}

func (auth *AuthenticationService) LoginUser(token *entities.AuthSet, c *gin.Context) error {
	if token == nil {
		return errors.New("token AuthSet is nil")
	}
	if c == nil {
		return errors.New("gin context is nil")
	}
	setLoginCookies(token, c, cookieDomain(), secureCookies())
	return nil
}

func setLoginCookies(token *entities.AuthSet, c *gin.Context, domain string, secure bool) {
	c.SetCookie(config.CookieAuthToken, token.AuthToken, config.AuthTokenCookieExpiry, "/", domain, secure, true)
	c.SetCookie(config.CookieRefreshToken, token.RefreshToken, config.RefreshTokenCookieExpiry, "/", domain, secure, true)
	c.SetCookie(config.CookieIsAuthenticated, "true", config.RefreshTokenCookieExpiry, "/", domain, secure, false)
}

func (auth *AuthenticationService) LogoutUser(c *gin.Context) error {
	claims, err := auth.TokenClaimsFromRequestAndValidate(c)
	if err != nil {
		log.Printf(config.LogLogoutTokenValidationFailed, err.Error())
		return err
	}

	invalidateCookies(c, cookieDomain(), secureCookies())
	log.Printf(config.LogLogoutUserSuccess, claims.UserID)
	return nil
}

func invalidateCookies(c *gin.Context, domain string, secure bool) {
	c.SetCookie(config.CookieAuthToken, "", 3600, "/", domain, secure, true)
	c.SetCookie(config.CookieRefreshToken, "", 3600, "/", domain, secure, true)
	c.SetCookie(config.CookieIsAuthenticated, "false", 3600, "/", domain, secure, false)
}

func secureCookies() bool {
	if os.Getenv("GO_ENV") == "development" {
		return false
	}
	return true
}

func cookieDomain() string {
	return os.Getenv("COOKIE_DOMAIN")
}
