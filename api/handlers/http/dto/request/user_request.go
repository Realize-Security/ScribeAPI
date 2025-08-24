package request

import "strings"

type UserRegistration struct {
	FirstName       string `json:"firstName" validate:"required,name_length,name_pattern"`
	LastName        string `json:"lastName" validate:"required,name_length,name_pattern"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,passwords_match,password_length"`
	ConfirmPassword string `json:"confirmPassword" validate:"required"`
	TermsAccepted   bool   `json:"termsAccepted,default:false" validate:"required"`
}

type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (u *UserRegistration) Sanitize() {
	u.FirstName = strings.TrimSpace(u.FirstName)
	u.LastName = strings.TrimSpace(u.LastName)
	u.Email = strings.TrimSpace(strings.ToLower(u.Email))
}
