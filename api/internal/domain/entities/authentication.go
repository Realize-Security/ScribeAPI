package entities

import "github.com/golang-jwt/jwt/v5"

type AuthSet struct {
	AuthToken    string
	RefreshToken string
	JTI          string
}

type JWTCustomClaims struct {
	UserID  int
	TokenID string
	jwt.RegisteredClaims
}

type SessionState struct {
	JTI   string
	Roles []string
}

type Claims interface {
	GetUserID() (string, error)
}

func (c JWTCustomClaims) GetUserID() (int, error) {
	return c.UserID, nil
}

func (c JWTCustomClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

func (c JWTCustomClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

func (c JWTCustomClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.NotBefore, nil
}

func (c JWTCustomClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c JWTCustomClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c JWTCustomClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}
