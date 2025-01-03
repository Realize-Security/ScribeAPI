package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type AuthenticationRepository interface {
	IsAuthenticated() gin.HandlerFunc
	PasswordsMatch(hashed, plain string) bool
	HashPassword(pwd string) (string, error)
	GenerateAuthToken(userUUID string) (*entities.AuthSet, error)
	TokenClaimsFromRequestAndValidate(c *gin.Context) (entities.JWTCustomClaims, error)
	GetClaimsFromContext(c *gin.Context) (entities.JWTCustomClaims, error)
	GenerateRefreshToken(userID string) (string, error)
	ValidateRefreshToken(token string) (string, error)
	RevokeRefreshToken(userID string) error
}

type AuthenticationService struct{}

type SessionTokenGenerator struct {
	mu sync.Mutex
}

func NewAuthenticationService() *AuthenticationService {
	return &AuthenticationService{}
}

// IsAuthenticated validates a user authentication token
func (auth *AuthenticationService) IsAuthenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := validateRequestToken(c)
		if err != nil {
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

// GenerateAuthToken generates an authentication token containing a user UUID and permissions
func (auth *AuthenticationService) GenerateAuthToken(userUUID string) (*entities.AuthSet, error) {
	_, e := uuid.FromString(userUUID)
	if e != nil {
		return nil, e
	}
	// JTI will be used as the session hash
	generator := new(SessionTokenGenerator)
	if generator == nil {
		log.Printf("unable to generate SessionTokenGenerator instance")
		return nil, gin.Error{}
	}
	jti, err := generator.createJtiSessionValue()
	if err != nil {
		return nil, err
	}

	if !jtiTokenIsValid(jti) {
		return nil, gin.Error{}
	}

	claims := entities.JWTCustomClaims{
		UserID: userUUID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AuthTokenExpiry)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    config.ApiName,
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	ss, err := token.SignedString([]byte(config.HMACSecret))
	if err != nil {
		return nil, err
	}

	rt, err := auth.GenerateRefreshToken(userUUID)
	if err != nil {
		log.Printf("unable to generate %s for: %s", config.CookieRefreshToken, userUUID)
		return nil, err
	}

	as := entities.AuthSet{
		AuthToken:    ss,
		RefreshToken: rt,
		JTI:          claims.RegisteredClaims.ID,
	}

	return &as, nil
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

func jtiTokenIsValid(jti string) bool {
	if len(jti) < 64 {
		log.Printf("generated jti was too short: %s", jti)
		return false
	}
	return true
}

// getTokenFromRequest receives a *gin.Context from a user request and extracts the JWT from the Authorization header
func getTokenFromRequest(c *gin.Context) (string, error) {
	bearer := c.Request.Header.Get(config.AuthorizationHeader)
	strArr := strings.Split(bearer, " ")
	if len(strArr) == 2 {
		log.Println(config.LogAuthHeaderSuccess)
		return strArr[1], nil
	}
	err := errors.New(config.LogAuthHeaderNotFound)
	log.Printf(err.Error())
	return "", err
}

// extractTokenFromString extracts claims from a token string but does NOT validate the signature
func extractTokenFromString(tokenString string) (jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &entities.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.HMACSecret), nil
	})
	if err != nil {
		log.Printf(err.Error())
		return jwt.Token{}, err
	}
	return *token, nil
}

func tokenIsValid(token jwt.Token) bool {
	if _, ok := token.Claims.(*entities.JWTCustomClaims); ok && token.Valid {
		return true
	} else {
		failed := errors.New(config.LogAuthTokenValidationFailed)
		log.Printf(failed.Error())
		return false
	}
}

// validateTokenSignature validates auth token signature
func validateTokenSignature(tokenString string) (jwt.Token, error) {
	token, err := extractTokenFromString(tokenString)
	if err != nil {
		return jwt.Token{}, err
	}
	if tokenIsValid(token) {
		return token, nil
	} else {
		failed := errors.New(config.LogAuthTokenValidationFailed)
		log.Printf(failed.Error())
		return jwt.Token{}, failed
	}
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
				ID:        claims.UserID,
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
	ts, pErr := getTokenFromRequest(c)
	if pErr != nil {
		return e, pErr
	}
	token, vErr := validateTokenSignature(ts)
	if vErr != nil {
		return e, vErr
	}
	claims, err := extractClaimsFromToken(&token)
	if err != nil {
		return e, err
	}
	return claims, nil
}

func (auth *AuthenticationService) GenerateRefreshToken(userUUID string) (string, error) {
	claims := entities.RefreshTokenClaims{
		UserUUID:  userUUID,
		TokenID:   uuid.Must(uuid.NewV4()).String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.RefreshTokenExpiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    config.ApiName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.RefreshSecret))
}

func (auth *AuthenticationService) ValidateRefreshToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &entities.RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.RefreshSecret), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*entities.RefreshTokenClaims); ok && token.Valid {
		return claims.UserUUID, nil
	}

	return "", errors.New("invalid refresh token")
}

func (auth *AuthenticationService) RevokeRefreshToken(userUUID string) error {
	// Implementation depends on your storage mechanism
	// Could update user in database to clear refresh token
	return nil
}

func tokenClaimsFromRequestNoValidate(c *gin.Context) (entities.JWTCustomClaims, error) {
	e := entities.JWTCustomClaims{}
	ts, pErr := getTokenFromRequest(c)
	if pErr != nil {
		return e, pErr
	}
	t, err := extractTokenFromString(ts)
	if err != nil {
		return e, err
	}
	claims, err := extractClaimsFromToken(&t)
	return claims, nil
}

// validateRequestToken parses Authorization headers, validates tokens and extracts claims
func validateRequestToken(c *gin.Context) error {
	ts, pErr := getTokenFromRequest(c)
	if pErr != nil {
		return pErr
	}
	_, vErr := validateTokenSignature(ts)
	if vErr != nil {
		return vErr
	}
	return nil
}

// GetClaimsFromContext returns entities.JWTCustomClaims from a request context. This does NOT validate the token.
func (auth *AuthenticationService) GetClaimsFromContext(c *gin.Context) (entities.JWTCustomClaims, error) {
	return tokenClaimsFromRequestNoValidate(c)
}
