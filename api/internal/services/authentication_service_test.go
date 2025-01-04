package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type AuthServiceTestSuite struct {
	suite.Suite
	auth *AuthenticationService
}

func TestAuthServiceSuite(t *testing.T) {
	suite.Run(t, new(AuthServiceTestSuite))
}

func (s *AuthServiceTestSuite) SetupTest() {
	var err error
	s.auth, err = NewAuthenticationService()
	require.NoError(s.T(), err)
}

// Helper function to create expired tokens
func createExpiredToken(auth *AuthenticationService, userUUID string, isRefresh bool) string {
	generator := new(SessionTokenGenerator)
	jti, _ := generator.createJtiSessionValue()

	claims := entities.JWTCustomClaims{
		UserUUID: userUUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			Issuer:    config.ApiName,
			ID:        jti,
		},
	}

	var token *jwt.Token
	if isRefresh {
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		signedToken, _ := token.SignedString(auth.keys.refreshSecret)
		return signedToken
	}

	token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, _ := token.SignedString(auth.keys.authPrivateKey)
	return signedToken
}

func (s *AuthServiceTestSuite) TestGenerateAuthToken() {
	s.Run("generates valid auth token", func() {
		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		authSet, err := s.auth.GenerateAuthToken(userUUID)

		assert.NoError(s.T(), err)
		assert.NotNil(s.T(), authSet)
		assert.NotEmpty(s.T(), authSet.AuthToken)
		assert.NotEmpty(s.T(), authSet.RefreshToken)
		assert.NotEmpty(s.T(), authSet.JTI)

		// Validate the generated tokens
		token, err := validateTokenSignature(s.auth, authSet.AuthToken)
		assert.NoError(s.T(), err)
		assert.True(s.T(), token.Valid)

		claims, ok := token.Claims.(*entities.JWTCustomClaims)
		assert.True(s.T(), ok)
		assert.Equal(s.T(), userUUID, claims.UserUUID)
	})

	s.Run("fails with invalid UUID", func() {
		userUUID := "invalid-uuid"
		authSet, err := s.auth.GenerateAuthToken(userUUID)

		assert.Error(s.T(), err)
		assert.Nil(s.T(), authSet)
	})
}

func (s *AuthServiceTestSuite) TestIsAuthenticated() {
	s.Run("allows authenticated requests", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Create a test request with valid cookies
		req := httptest.NewRequest("GET", "/", nil)
		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		authSet, err := s.auth.GenerateAuthToken(userUUID)
		require.NoError(s.T(), err)

		req.AddCookie(&http.Cookie{
			Name:  config.CookieAuthToken,
			Value: authSet.AuthToken,
		})
		req.AddCookie(&http.Cookie{
			Name:  config.CookieRefreshToken,
			Value: authSet.RefreshToken,
		})

		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusOK, w.Code)
	})

	s.Run("allowed if auth_token is invalid and refresh_token is valid", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("GET", "/", nil)
		userUUID := "123e4567-e89b-12d3-a456-426614174000"

		expiredAuthToken := createExpiredToken(s.auth, userUUID, false)
		refreshToken, err := s.auth.GenerateRefreshToken(userUUID)
		require.NoError(s.T(), err)

		req.AddCookie(&http.Cookie{
			Name:  config.CookieAuthToken,
			Value: expiredAuthToken,
		})
		req.AddCookie(&http.Cookie{
			Name:  config.CookieRefreshToken,
			Value: refreshToken,
		})

		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusOK, w.Code)

		// Verify new cookies were set
		cookies := w.Result().Cookies()
		var foundNewAuth, foundNewRefresh bool
		for _, cookie := range cookies {
			if cookie.Name == config.CookieAuthToken && cookie.Value != expiredAuthToken {
				foundNewAuth = true
			}
			if cookie.Name == config.CookieRefreshToken && cookie.Value != refreshToken {
				foundNewRefresh = true
			}
		}
		assert.True(s.T(), foundNewAuth, "Should have set new auth token")
		assert.True(s.T(), foundNewRefresh, "Should have set new refresh token")
	})

	s.Run("blocks if both tokens are invalid", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("GET", "/", nil)
		userUUID := "123e4567-e89b-12d3-a456-426614174000"

		expiredAuthToken := createExpiredToken(s.auth, userUUID, false)
		expiredRefreshToken := createExpiredToken(s.auth, userUUID, true)

		req.AddCookie(&http.Cookie{
			Name:  config.CookieAuthToken,
			Value: expiredAuthToken,
		})
		req.AddCookie(&http.Cookie{
			Name:  config.CookieRefreshToken,
			Value: expiredRefreshToken,
		})

		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusForbidden, w.Code)
	})
}

func (s *AuthServiceTestSuite) TestValidateRefreshToken() {
	s.Run("validates valid refresh token", func() {
		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		refreshToken, err := s.auth.GenerateRefreshToken(userUUID)
		require.NoError(s.T(), err)

		resultUUID, err := s.auth.ValidateRefreshToken(refreshToken)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), userUUID, resultUUID)
	})

	s.Run("rejects expired refresh token", func() {
		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		expiredToken := createExpiredToken(s.auth, userUUID, true)

		resultUUID, err := s.auth.ValidateRefreshToken(expiredToken)
		assert.Error(s.T(), err)
		assert.Empty(s.T(), resultUUID)
	})

	s.Run("rejects token with invalid signing method", func() {
		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		claims := entities.JWTCustomClaims{
			UserUUID: userUUID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedToken, _ := token.SignedString(s.auth.keys.authPrivateKey)

		resultUUID, err := s.auth.ValidateRefreshToken(signedToken)
		assert.Error(s.T(), err)
		assert.Empty(s.T(), resultUUID)
		assert.Contains(s.T(), err.Error(), "unexpected signing method")
	})
}

func (s *AuthServiceTestSuite) TestTokenClaimsFromRequestAndValidate() {
	s.Run("extracts claims from valid token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userUUID := "123e4567-e89b-12d3-a456-426614174000"
		authSet, err := s.auth.GenerateAuthToken(userUUID)
		require.NoError(s.T(), err)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		c.Request = req

		claims, err := s.auth.TokenClaimsFromRequestAndValidate(c)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), userUUID, claims.UserUUID)
	})

	s.Run("fails with invalid token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: "invalid-token"})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: "invalid-token"})
		c.Request = req

		claims, err := s.auth.TokenClaimsFromRequestAndValidate(c)
		assert.Error(s.T(), err)
		assert.Empty(s.T(), claims.UserUUID)
	})
}
