package middleware

import (
	"net/http"
	"strings"

	"github.com/JosMiguelMM/Go-REST-WebSockets/handlers"
	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/golang-jwt/jwt/v5"
)

var (
	NO_AUTH_NEEDED = []string{
		"login",
		"signup",
	}
)

func shouldCheckAuth(route string) bool {
	for _, path := range NO_AUTH_NEEDED {
		if strings.Contains(route, path) {
			return false
		}
	}
	return true
}

func CheckAuthMiddleware(s server.Server) func(h http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldCheckAuth(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			tokenString := strings.TrimSpace(r.Header.Get("Authorization"))
			_, err := jwt.ParseWithClaims(tokenString, &models.AppClaims{},
				func(token *jwt.Token) (any, error) {
					return []byte(s.Config().JwtSecret), nil
				})
			if err != nil {
				handlers.SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
