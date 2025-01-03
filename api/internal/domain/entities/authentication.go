package entities

import "github.com/golang-jwt/jwt/v5"

type AuthSet struct {
	AuthToken    string `json:"auth_token"`
	RefreshToken string `json:"refresh_token"`
	JTI          string `json:"jti"`
}

type RefreshTokenClaims struct {
	UserUUID  string           `json:"user_uuid"`
	TokenID   string           `json:"token_id"`
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  jwt.ClaimStrings `json:"aud,omitempty"`
}

func (c RefreshTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

func (c RefreshTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

func (c RefreshTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.NotBefore, nil
}

func (c RefreshTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c RefreshTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c RefreshTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}
