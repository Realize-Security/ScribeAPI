package services

import (
	"Scribe/internal/domain/entities"
	"Scribe/internal/infrastructure/cache"
	"Scribe/pkg/config"
	"fmt"
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

type fakeUserRepo struct{}

func (f *fakeUserRepo) Create(user *entities.UserDBModel) error {
	// Stub implementation: do nothing and return nil since not used in tests
	return nil
}

func (f *fakeUserRepo) FindByEmail(email string) (*entities.UserDBModel, error) {
	// Stub implementation: return nil and error since not used in tests
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeUserRepo) FindByID(id int) (*entities.UserDBModel, error) {
	if id < 0 {
		return nil, fmt.Errorf("invalid user ID")
	}
	return &entities.UserDBModel{
		Base: entities.Base{
			ID: id,
		},
		Roles: []*entities.RoleDBModel{},
	}, nil
}

func (s *AuthServiceTestSuite) SetupTest() {
	ur := &fakeUserRepo{}
	var err error
	s.auth, err = NewAuthenticationService(ur)
	require.NoError(s.T(), err)
}

func (s *AuthServiceTestSuite) TestPasswordHandling() {
	hash, err := s.auth.HashPassword("testpass")
	assert.NoError(s.T(), err)
	assert.True(s.T(), s.auth.PasswordsMatch(hash, "testpass"))
	assert.False(s.T(), s.auth.PasswordsMatch(hash, "wrongpass"))
}

// Helper function to create expired tokens
func createExpiredToken(auth *AuthenticationService, userID int, isRefresh bool) string {
	generator := new(SessionTokenGenerator)
	jti, _ := generator.createJtiSessionValue()

	claims := entities.JWTCustomClaims{
		UserID: userID,
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
		userID := 1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)

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
		assert.Equal(s.T(), userID, claims.UserID)
	})

	s.Run("fails with an invalid int", func() {
		userID := -1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)

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
		userID := 1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
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
		userID := 1

		expiredAuthToken := createExpiredToken(s.auth, userID, false)
		refreshToken, err := s.auth.GenerateRefreshToken(userID)
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
		userID := 1

		expiredAuthToken := createExpiredToken(s.auth, userID, false)
		expiredRefreshToken := createExpiredToken(s.auth, userID, true)

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
		userID := 1
		refreshToken, err := s.auth.GenerateRefreshToken(userID)
		require.NoError(s.T(), err)

		resultID, err := s.auth.ValidateRefreshToken(refreshToken)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), userID, resultID)
	})

	s.Run("rejects expired refresh token", func() {
		userID := 1
		expiredToken := createExpiredToken(s.auth, userID, true)

		resultUUID, err := s.auth.ValidateRefreshToken(expiredToken)
		assert.Error(s.T(), err)
		assert.Equal(s.T(), -1, resultUUID)
	})

	s.Run("rejects token with invalid signing method", func() {
		userID := 1
		claims := entities.JWTCustomClaims{
			UserID: userID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedToken, _ := token.SignedString(s.auth.keys.authPrivateKey)

		resultUUID, err := s.auth.ValidateRefreshToken(signedToken)
		assert.Error(s.T(), err)
		assert.Equal(s.T(), -1, resultUUID)
		assert.Contains(s.T(), err.Error(), "unexpected signing method")
	})
}

func (s *AuthServiceTestSuite) TestTokenClaimsFromRequestAndValidate() {
	s.Run("extracts claims from valid token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userID := 1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		c.Request = req

		claims, err := s.auth.TokenClaimsFromRequestAndValidate(c)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), userID, claims.UserID)
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
		assert.Empty(s.T(), claims.UserID)
	})
}

func (s *AuthServiceTestSuite) TestLogoutUser() {
	s.Run("successfully logs out user and invalidates cookies", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Set up an authenticated user
		userID := 1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// Create test request with cookies
		req := httptest.NewRequest("GET", "/api/logout", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		req.AddCookie(&http.Cookie{Name: config.UnsafeCookieIsAuthenticated, Value: "true"})
		c.Request = req

		// Perform logout
		err = s.auth.LogoutUser(c)

		// Verify the results
		assert.NoError(s.T(), err)

		// Check that cookies were invalidated
		cookies := w.Result().Cookies()
		var foundAuthCookie, foundRefreshCookie, foundIsAuthCookie bool
		for _, cookie := range cookies {
			switch cookie.Name {
			case config.CookieAuthToken:
				assert.Equal(s.T(), "", cookie.Value)
				assert.Equal(s.T(), 0, cookie.MaxAge)
				foundAuthCookie = true
			case config.CookieRefreshToken:
				assert.Equal(s.T(), "", cookie.Value)
				assert.Equal(s.T(), 0, cookie.MaxAge)
				foundRefreshCookie = true
			case config.UnsafeCookieIsAuthenticated:
				assert.Equal(s.T(), "false", cookie.Value)
				assert.Equal(s.T(), 3600, cookie.MaxAge)
				foundIsAuthCookie = true
			}
		}
		assert.True(s.T(), foundAuthCookie, "Auth cookie should be present")
		assert.True(s.T(), foundRefreshCookie, "Refresh cookie should be present")
		assert.True(s.T(), foundIsAuthCookie, "IsAuthenticated cookie should be present")
	})

	s.Run("returns error when no auth cookies present", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("GET", "/api/logout", nil)
		c.Request = req

		err := s.auth.LogoutUser(c)

		assert.Error(s.T(), err)
		assert.Contains(s.T(), err.Error(), config.LogExtractAuthCookiesError)
	})

	s.Run("returns error with invalid auth token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("GET", "/api/logout", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: "invalid-token"})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: "invalid-refresh-token"})
		c.Request = req

		err := s.auth.LogoutUser(c)

		assert.Error(s.T(), err)
		assert.Contains(s.T(), err.Error(), "token is malformed")
	})
}

func (s *AuthServiceTestSuite) TestGenerateAuthTokenCachesJTI() {
	s.Run("stores JTI in cache when generating auth token", func() {
		userID := 123

		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// Verify JTI is stored in cache
		sc := cache.SessionCache.Get()
		value, exists := sc.Get(userID)
		assert.True(s.T(), exists, "User session should exist in cache")

		assert.Equal(s.T(), authSet.JTI, value.JTI, "Cached JTI should match token JTI")
	})

	s.Run("overwrites existing cache entry for same user", func() {
		userID := 1

		// Generate first token
		authSet1, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// Generate second token for same user
		authSet2, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// Verify cache contains the latest JTI
		sc := cache.SessionCache.Get()
		value, exists := sc.Get(userID)
		assert.True(s.T(), exists)

		assert.Equal(s.T(), authSet2.JTI, value.JTI, "Cache should contain the latest JTI")
		assert.NotEqual(s.T(), authSet1.JTI, value.JTI, "Should not contain old JTI")
	})
}

func (s *AuthServiceTestSuite) TestAuthenticationRequiresCacheEntry() {
	s.Run("blocks authentication when user not in cache despite valid refresh token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userID := 1

		// Create expired auth token and valid refresh token
		expiredAuthToken := createExpiredToken(s.auth, userID, false)
		refreshToken, err := s.auth.GenerateRefreshToken(userID)
		require.NoError(s.T(), err)

		// Explicitly ensure user is NOT in cache
		sc := cache.SessionCache.Get()
		sc.Delete(userID)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: expiredAuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: refreshToken})
		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusForbidden, w.Code)
	})

	s.Run("allows authentication when user in cache with valid refresh token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userID := 1

		session := entities.SessionState{
			JTI: "some-jti",
		}

		// Put user in cache first
		addSessionToCache(userID, session, config.CacheNoTTLExpiry)

		// Create expired auth token and valid refresh token
		expiredAuthToken := createExpiredToken(s.auth, userID, false)
		refreshToken, err := s.auth.GenerateRefreshToken(userID)
		require.NoError(s.T(), err)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: expiredAuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: refreshToken})
		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusOK, w.Code)

		// Verify new auth token was issued and cache updated
		cookies := w.Result().Cookies()
		var foundNewAuth bool
		for _, cookie := range cookies {
			if cookie.Name == config.CookieAuthToken && cookie.Value != expiredAuthToken {
				foundNewAuth = true
				break
			}
		}
		assert.True(s.T(), foundNewAuth, "Should have issued new auth token")
	})
}

func (s *AuthServiceTestSuite) TestLogoutClearsCache() {
	s.Run("removes user from cache on successful logout", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userID := 1
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// Verify user is in cache before logout
		sc := cache.SessionCache.Get()
		_, exists := sc.Get(userID)
		assert.True(s.T(), exists, "User should be in cache before logout")

		req := httptest.NewRequest("GET", "/api/logout", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		c.Request = req

		err = s.auth.LogoutUser(c)
		assert.NoError(s.T(), err)

		// Verify user was removed from cache
		_, exists = sc.Get(userID)
		assert.False(s.T(), exists, "User should be removed from cache after logout")
	})
}

func (s *AuthServiceTestSuite) TestCacheBasedTokenRevocation() {
	s.Run("valid tokens become invalid when user removed from cache", func() {
		userID := 1

		// Generate valid tokens and verify they work
		authSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)

		// First request should succeed
		w1 := httptest.NewRecorder()
		c1, _ := gin.CreateTestContext(w1)
		req1 := httptest.NewRequest("GET", "/", nil)
		req1.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req1.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		c1.Request = req1

		middleware1 := s.auth.IsAuthenticated()
		middleware1(c1)
		assert.Equal(s.T(), http.StatusOK, w1.Code, "First request should succeed")

		// Remove user from cache (simulating logout or revocation)
		sc := cache.SessionCache.Get()
		sc.Delete(userID)

		// Second request with same tokens should fail
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: authSet.AuthToken})
		req2.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: authSet.RefreshToken})
		c2.Request = req2

		middleware2 := s.auth.IsAuthenticated()
		middleware2(c2)
		assert.Equal(s.T(), http.StatusForbidden, w2.Code, "Second request should fail after cache removal")
	})
}

func (s *AuthServiceTestSuite) TestAuthTokenRefreshUpdatesCache() {
	s.Run("updates cache with new JTI when refreshing auth token", func() {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		userID := 1

		// Generate initial auth set and get the JTI
		initialAuthSet, err := s.auth.GenerateAuthTokenFromUserID(userID)
		require.NoError(s.T(), err)
		initialJTI := initialAuthSet.JTI

		// Create expired auth token to trigger refresh
		expiredAuthToken := createExpiredToken(s.auth, userID, false)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: config.CookieAuthToken, Value: expiredAuthToken})
		req.AddCookie(&http.Cookie{Name: config.CookieRefreshToken, Value: initialAuthSet.RefreshToken})
		c.Request = req

		middleware := s.auth.IsAuthenticated()
		middleware(c)

		assert.Equal(s.T(), http.StatusOK, w.Code)

		// Verify cache was updated with new JTI
		sc := cache.SessionCache.Get()
		value, exists := sc.Get(userID)
		assert.True(s.T(), exists)

		assert.NotEqual(s.T(), initialJTI, value.JTI, "JTI should be updated after refresh")
		assert.NotEmpty(s.T(), value.JTI, "New JTI should not be empty")
	})
}
