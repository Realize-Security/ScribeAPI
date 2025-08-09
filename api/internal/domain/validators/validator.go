package validators

import (
	"errors"
	"fmt"
	"log"

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

// ValidateStruct is a generic function that validates any struct type T using the validator library.
// It takes an instance of T (or *T), attempts to validate it (assuming T has validation tags),
// and returns a map where keys are field namespaces (e.g., 'User.Name') and values are slices of error messages to handle multiple failed tags per field.
func ValidateStruct[T any](target T) map[string][]string {
	validationErrors := make(map[string][]string)
	err := Validator.Struct(target)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			for _, v := range ve {
				msg := fmt.Sprintf("Validation for '%s' failed on '%s'", v.Field(), v.Tag())
				log.Printf("validation error: %s", msg)
				validationErrors[v.Namespace()] = append(validationErrors[v.Namespace()], msg)
			}
		} else {
			log.Printf("validation error: %s", err.Error())
			validationErrors["general"] = append(validationErrors["general"], err.Error())
		}
	}
	return validationErrors
}
