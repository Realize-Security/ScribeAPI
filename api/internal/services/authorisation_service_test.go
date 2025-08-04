package services_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"Scribe/internal/domain/entities"
	"Scribe/internal/infrastructure/cache"
	"Scribe/internal/services"
	"Scribe/pkg/config"

	"github.com/gin-gonic/gin"
	"net/http/httptest"
)

func setupCaches() {
	// Clear and populate permission cache for tests (assuming Cache has Clear and Set methods)
	permCache := cache.PermissionIDCache.Get()
	permCache.Clear()
	permCache.Set("user_list", 1, config.CacheNoTTLExpiry)
	permCache.Set("user_create", 2, config.CacheNoTTLExpiry)
	permCache.Set("user_read", 3, config.CacheNoTTLExpiry)

	// Clear session cache
	sessionCache := cache.SessionCache.Get()
	sessionCache.Clear()
}

func TestUserHasPermission_SessionNotFound(t *testing.T) {
	setupCaches()

	// No session set for user ID 1

	auth, _ := services.NewAuthorisationService(nil) // ur not used, pass nil

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	requester := &entities.UserDBModel{Base: entities.Base{ID: 1}}
	neededPermissions := []string{"user_list", "user_create"}

	auth.UserHasPermission(c, requester, neededPermissions)

	if !c.IsAborted() {
		t.Error("expected context to be aborted")
	}
	if w.Code != 403 {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestUserHasPermission_MissingPermission(t *testing.T) {
	setupCaches()

	// Set session with only one permission
	sessionCache := cache.SessionCache.Get()
	sessionCache.Set(1, entities.SessionState{PermissionIDs: []int{1}}, config.CacheNoTTLExpiry) // Has "user_list" (ID 1), missing others

	auth, _ := services.NewAuthorisationService(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	requester := &entities.UserDBModel{Base: entities.Base{ID: 1}}
	neededPermissions := []string{"user_list", "user_create", "user_read"}

	// Capture log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	auth.UserHasPermission(c, requester, neededPermissions)

	if !c.IsAborted() {
		t.Error("expected context to be aborted")
	}
	if w.Code != 403 {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	logOutput := logBuf.String()
	expectedLog := config.LogUserUnauthorised
	expected := formatExpectedLog(expectedLog, 1, "user_create")
	if !strings.Contains(logOutput, expected) {
		t.Errorf("expected log to contain unauthorized message for missing permission, got: %s", logOutput)
	}
}

func TestUserHasPermission_HasAllPermissions(t *testing.T) {
	setupCaches()

	// Set session with all needed permissions
	sessionCache := cache.SessionCache.Get()
	sessionCache.Set(1, entities.SessionState{PermissionIDs: []int{1, 2, 3}}, config.CacheNoTTLExpiry)

	auth, _ := services.NewAuthorisationService(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	requester := &entities.UserDBModel{Base: entities.Base{ID: 1}}
	neededPermissions := []string{"user_list", "user_create", "user_read"}

	// Capture log to ensure no failure log
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	auth.UserHasPermission(c, requester, neededPermissions)

	if c.IsAborted() {
		t.Error("expected context not to be aborted")
	}
	if logBuf.String() != "" {
		t.Errorf("expected no log output for successful authorization, got: %s", logBuf.String())
	}
}

func TestLogFailedAuthorisation_FoundPermission(t *testing.T) {
	auth, _ := services.NewAuthorisationService(nil)

	requester := &entities.UserDBModel{Base: entities.Base{ID: 1}}
	needed := map[string]int{"user_create": 2, "user_read": 3}
	failedID := 2

	// Capture log
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	auth.LogFailedAuthorisation(requester, needed, failedID)

	logOutput := logBuf.String()
	expected := formatExpectedLog(config.LogUserUnauthorised, 1, "user_create")
	if !strings.Contains(logOutput, expected) {
		t.Errorf("expected log '%s', got '%s'", expected, logOutput)
	}
}

func TestLogFailedAuthorisation_NotFoundPermission(t *testing.T) {
	auth, _ := services.NewAuthorisationService(nil)

	requester := &entities.UserDBModel{Base: entities.Base{ID: 1}}
	needed := map[string]int{"user_create": 2}
	failedID := 999 // Not in needed

	// Capture log
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	auth.LogFailedAuthorisation(requester, needed, failedID)

	if logBuf.String() != "" {
		t.Errorf("expected no log output, got '%s'", logBuf.String())
	}
}

// Helper to format expected log; adjust based on actual config.LogUserUnauthorised format
func formatExpectedLog(format string, userID int, perm string) string {
	return fmt.Sprintf(format, userID, perm)
}
