package main

import jwt "github.com/dgrijalva/jwt-go"

// ErrorResponse is struct for sending error message with code.
type ErrorResponse struct {
	Code    int
	Message string
}

// SuccessResponse is struct for sending error message with code.
type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

// Claims is  a struct that will be encoded to a JWT.
// jwt.StandardClaims is an embedded type to provide expiry time
type Claims struct {
	Email string
	jwt.StandardClaims
}

// UserDetails is struct used for user details
type UserDetails struct {
	Name     string
	Email    string
	Password string
}

// FacebookUserDetails is struct used for user details
type FacebookUserDetails struct {
	ID    string
	Name  string
	Email string
}
