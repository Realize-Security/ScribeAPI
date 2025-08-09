package validators

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var nameRegex = regexp.MustCompile(`^(?:[A-ZÀ-ÖØ-Þa-zà-öø-ÿ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ']*(?:[-. ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ']*)*)?$`)

func nameLength(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	return len(name) >= config.MinUserLen && len(name) <= config.MaxUserLen
}

func namePattern(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	return nameRegex.MatchString(name)
}

func passwordsMatch(fl validator.FieldLevel) bool {
	user, ok := fl.Parent().Interface().(entities.UserRegistration)
	if !ok {
		return false
	}
	return user.Password == user.ConfirmPassword
}

func passwordLength(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	return len(password) >= config.MinPasswordLength
}

func emailNotInPassword(fl validator.FieldLevel) bool {
	user, ok := fl.Parent().Interface().(entities.UserRegistration)
	if !ok {
		return false
	}
	pass := strings.ToLower(user.Password)
	email := strings.ToLower(user.Email)
	return !strings.Contains(pass, email) && !strings.Contains(pass, reverseString(email))
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
