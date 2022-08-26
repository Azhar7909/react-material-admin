package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecretKey = []byte("jwt_secret_key")

// CreateJWT func will used to create the JWT while signing in and signing out
func CreateJWT(email string) (response string, err error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err == nil {
		return tokenString, nil
	}
	return "", err
}

// VerifyToken func will used to Verify the JWT Token while using APIS
func VerifyToken(tokenString string) (email string, err error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if token != nil {
		return claims.Email, nil
	}
	return "", err
}

// ShouldGenerateTheToken will return true/false if the token will expire within 60 seconds
func ShouldGenerateTheToken() bool {
	claims := &Claims{}
	return time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 60*time.Second
}
