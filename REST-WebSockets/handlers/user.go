package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	HASH_COST = 12
)

type ErrorResponse struct {
	Message string `json:"message"`
}

type SingUpLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SingUpResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// ... (justo después de tus structs)

// SendErrorResponse es una función de ayuda para enviar errores en formato JSON.
func SendErrorResponse(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

// ... (el resto de tus handlers)

func SingUpHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request = SingUpLoginRequest{}
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := ksuid.NewRandom()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), HASH_COST)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var user = models.User{
			Id:       id.String(),
			Email:    request.Email,
			Password: string(hashedPassword),
		}
		err = repository.InsertUser(r.Context(), &user)
		if err != nil {
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(ErrorResponse{Message: "User with this email already exists"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		var response SingUpResponse = SingUpResponse{
			ID:    id.String(),
			Email: request.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func LoginHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request = SingUpLoginRequest{}
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request payload"})
			return
		}
		user, err := repository.GetUserByEmail(r.Context(), request.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
			return
		}

		claims := models.AppClaims{
			UserId: user.Id,
			RegisteredClaims: jwt.RegisteredClaims{
				// Establecemos el tiempo de expiración (ej. 24 horas)
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				// Establecemos el tiempo de emisión
				IssuedAt: jwt.NewNumericDate(time.Now()),
				// Establecemos el emisor (opcional)
				Issuer: "my-app",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(s.Config().JwtSecret))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := LoginResponse{Token: tokenString}
		json.NewEncoder(w).Encode(response)
	}
}

func MeHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimSpace(r.Header.Get("Authorization"))
		token, err := jwt.ParseWithClaims(tokenString, &models.AppClaims{},
			func(token *jwt.Token) (any, error) {
				return []byte(s.Config().JwtSecret), nil
			})
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		if claims, ok := token.Claims.(*models.AppClaims); ok && token.Valid {
			user, err := repository.GetUserById(r.Context(), claims.UserId)
			if err != nil {
				SendErrorResponse(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(user)
		} else {
			SendErrorResponse(w, "An error has occurred", http.StatusInternalServerError)
			return
		}
	}

}
