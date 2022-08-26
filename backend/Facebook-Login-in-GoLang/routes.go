package main

import (
	"log"

	"github.com/gorilla/mux"
)

// AddApproutes will add the routes for the application
func AddApproutes(route *mux.Router) {

	log.Println("Loadeding Routes...")

	route.HandleFunc("/", RenderHome)

	route.HandleFunc("/profile", RenderProfile)

	route.HandleFunc("/login/facebook", InitFacebookLogin)

	route.HandleFunc("/facebook/callback", HandleFacebookLogin)

	route.HandleFunc("/userDetails", GetUserDetails).Methods("GET")

	log.Println("Routes are Loaded.")
}
