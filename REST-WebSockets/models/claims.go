package models

import "github.com/golang-jwt/jwt/v5"

type AppClaims struct {
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}
