package validators

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var nameRegex = regexp.MustCompile(`^(?:[A-ZÀ-ÖØ-Þa-zà-öø-ÿ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ']*(?:[-. ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ']*)*)?$`)

func validateUsername(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	return nameIsCompliant(name)
}

func validatePassword(fl validator.FieldLevel) bool {
	user, ok := fl.Parent().Interface().(entities.UserRegistration)
	if !ok {
		return false
	}
	email := user.Email
	password := user.Password

	return passwordIsCompliant(email, password)
}

func nameIsCompliant(name string) bool {
	if len(name) < config.MinUserLen || len(name) > config.MaxUserLen {
		return false
	}
	return nameRegex.MatchString(name)
}

func passwordIsCompliant(email, password string) bool {
	if len(password) < config.MinPasswordLength {
		return false
	}
	if emailInPassword(email, password) {
		return false
	}
	return true
}

// emailInPassword performs case-insensitive checks that no variation of email is in password
func emailInPassword(email, password string) bool {
	email = strings.ToLower(email)
	password = strings.ToLower(password)
	return email == password || strings.Contains(email, password) || strings.Contains(reverseString(email), password)
}

func reverseString(s string) string {
	n := len(s)
	runes := make([]rune, n)
	for _, r := range s {
		n--
		runes[n] = r
	}
	return string(runes[n:])
}
