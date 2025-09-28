package middleware

import (
	"net/http"

	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
)

var (
	NO_AUTH_NEEDED = []string{
		"/login",
		"/singup",
	}
)

func CheckAuthMiddleware(s server.Server) func(h http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		})
	}
}
