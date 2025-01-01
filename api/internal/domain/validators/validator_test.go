package validators

import (
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInitValidator(t *testing.T) {
	t.Run("returns a type of *validator.Validate", func(t *testing.T) {
		v := InitValidator()
		assert.IsType(t, &validator.Validate{}, v)
	})
}
