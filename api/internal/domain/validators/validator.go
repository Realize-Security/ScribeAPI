package validators

import (
	"github.com/go-playground/validator/v10"
)

var Validator *validator.Validate

func InitValidator() *validator.Validate {
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.RegisterValidation("first_or_last_name", validateUsername)
	if err != nil {
		panic(err)
	}
	err = validate.RegisterValidation("validate_password", validatePassword)
	if err != nil {
		panic(err)
	}
	return validate
}
