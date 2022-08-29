package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/oauth2"
)

// RenderHome Rendering the Home Page
func RenderHome(response http.ResponseWriter, request *http.Request) {
	http.ServeFile(response, request, "views/index.html")
}

// RenderProfile Rendering the ProfileHome Page
func RenderProfile(response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, "http://localhost:3000/#/app/dashboard", http.StatusSeeOther)
}

// InitFacebookLogin function will initiate the Facebook Login
func InitFacebookLogin(response http.ResponseWriter, request *http.Request) {
	var OAuth2Config = GetFacebookOAuthConfig()
	url := OAuth2Config.AuthCodeURL(GetRandomOAuthStateString())
	http.Redirect(response, request, url, http.StatusTemporaryRedirect)
}

// HandleFacebookLogin function will handle the Facebook Login Callback
func HandleFacebookLogin(response http.ResponseWriter, request *http.Request) {
	var state = request.FormValue("state")
	var code = request.FormValue("code")

	if state != GetRandomOAuthStateString() {
		http.Redirect(response, request, "/?invalidlogin=true", http.StatusTemporaryRedirect)
	}

	var OAuth2Config = GetFacebookOAuthConfig()

	token, err := OAuth2Config.Exchange(oauth2.NoContext, code)

	if err != nil || token == nil {
		http.Redirect(response, request, "/?invalidlogin=true", http.StatusTemporaryRedirect)
	}

	fbUserDetails, fbUserDetailsError := GetUserInfoFromFacebook(token.AccessToken)

	if fbUserDetailsError != nil {
		http.Redirect(response, request, "/?invalidlogin=true", http.StatusTemporaryRedirect)
	}

	authToken, authTokenError := SignInUser(fbUserDetails)

	if authTokenError != nil {
		http.Redirect(response, request, "/?invalidlogin=true", http.StatusTemporaryRedirect)
	}

	cookie := &http.Cookie{Name: "Authorization", Value: "Bearer " + authToken, Path: "/"}
	http.SetCookie(response, cookie)

	http.Redirect(response, request, "/profile", http.StatusTemporaryRedirect)
}

// SignInUser Used for Signing In the Users
func SignInUser(facebookUserDetails FacebookUserDetails) (string, error) {
	var result UserDetails

	if facebookUserDetails == (FacebookUserDetails{}) {
		return "", errors.New("User details Can't be empty")
	}

	if facebookUserDetails.Email == "" {
		return "", errors.New("Last Name can't be empty")
	}

	if facebookUserDetails.Name == "" {
		return "", errors.New("Password can't be empty")
	}

	collection := Client.Database("test").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	_ = collection.FindOne(ctx, bson.M{
		"email": facebookUserDetails.Email,
	}).Decode(&result)

	defer cancel()

	if result == (UserDetails{}) {
		_, registrationError := collection.InsertOne(ctx, bson.M{
			"email":    facebookUserDetails.Email,
			"password": "",
			"name":     facebookUserDetails.Name,
		})
		defer cancel()

		if registrationError != nil {
			return "", errors.New("Error occurred registration")
		}
	}

	tokenString, _ := CreateJWT(facebookUserDetails.Email)

	if tokenString == "" {
		return "", errors.New("Unable to generate Auth token")
	}

	return tokenString, nil
}

// GetUserDetails Used for getting the user details using user token
func GetUserDetails(response http.ResponseWriter, request *http.Request) {
	var result UserDetails
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "It's not you it's me.",
	}
	bearerToken := request.Header.Get("Authorization")
	var authorizationToken = strings.Split(bearerToken, " ")[1]

	email, _ := VerifyToken(authorizationToken)
	if email == "" {
		returnErrorResponse(response, request, errorResponse)
	} else {
		collection := Client.Database("test").Collection("users")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err = collection.FindOne(ctx, bson.M{
			"email": email,
		}).Decode(&result)

		defer cancel()

		if err != nil {
			returnErrorResponse(response, request, errorResponse)
		} else {
			var successResponse = SuccessResponse{
				Code:     http.StatusOK,
				Message:  "You are logged in successfully",
				Response: result.Name,
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Write(successJSONResponse)
		}
	}
}

func returnErrorResponse(response http.ResponseWriter, request *http.Request, errorMesage ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMesage.Code, Message: errorMesage.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(errorMesage.Code)
	response.Write(jsonResponse)
}
