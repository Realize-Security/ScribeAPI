package validators

import (
	"Scribe/internal/domain/entities"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const validPass = "maryhadalittlelamb"

var newUser = entities.UserRegistration{
	FirstName:       "Gandalf-Istar",
	LastName:        "Greybeard",
	Email:           "mail@email.com",
	Password:        validPass,
	ConfirmPassword: validPass,
}

func TestNameValidation(t *testing.T) {
	t.Run("Names can contain upper and lower-case characters and hyphens.", func(t *testing.T) {
		res := nameIsCompliant(newUser.FirstName)
		assert.Equal(t, true, res)

		res = nameIsCompliant(strings.ToLower(newUser.FirstName))
		assert.Equal(t, true, res)
	})
	t.Run("Names can contain upper and lower-case characters and no hyphen", func(t *testing.T) {
		newUser.FirstName = "Gandalf"

		res := nameIsCompliant(newUser.LastName)
		assert.Equal(t, true, res)

		res = nameIsCompliant(strings.ToLower(newUser.LastName))
		assert.Equal(t, true, res)
	})

	t.Run("Names between and including 1 and 30 characters are valid", func(t *testing.T) {
		res := nameIsCompliant("A")
		assert.Equal(t, true, res)

		res = nameIsCompliant(strings.Repeat("a", 30))
		assert.Equal(t, true, res)

		res = nameIsCompliant(strings.Repeat("A", 15))
		assert.Equal(t, true, res)
	})

	t.Run("Names shorter than 1 character and longer than 30 are invalid", func(t *testing.T) {
		newUser.FirstName = ""
		res := nameIsCompliant(newUser.FirstName)
		assert.Equal(t, false, res)

		newUser.FirstName = strings.Repeat("A", 31)
		res = nameIsCompliant(newUser.FirstName)
		assert.Equal(t, false, res)

	})
}

func TestPasswordIsValid(t *testing.T) {
	t.Run("Passwords less than 16 characters are invalid", func(t *testing.T) {
		res := passwordIsCompliant(newUser.Email, strings.Repeat("A", 15))
		assert.Equal(t, false, res)
	})

	t.Run("Passwords the same as the user email are invalid", func(t *testing.T) {
		res := passwordIsCompliant(newUser.Email, newUser.Email)
		assert.Equal(t, false, res)
	})

	t.Run("Passwords which are the email backwards are invalid", func(t *testing.T) {
		res := passwordIsCompliant(reverseString(newUser.Email), newUser.Email)
		assert.Equal(t, false, res)
	})
	t.Run("Passwords which contain the email as a substring are invalid", func(t *testing.T) {
		res := passwordIsCompliant("AA"+newUser.Email+"BB", newUser.Email)
		assert.Equal(t, false, res)
	})
}
