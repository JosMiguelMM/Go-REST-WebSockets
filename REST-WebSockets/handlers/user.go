// Package handlers contiene los manejadores de rutas HTTP para la API REST.
// Proporciona endpoints para autenticación, perfil de usuario y operaciones básicas.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/JosMiguelMM/Go-REST-WebSockets/auth"
	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

// HASH_COST define el costo de encriptación para bcrypt.
// Un valor mayor aumenta la seguridad pero reduce el rendimiento.
const HASH_COST = 15

// ErrorResponse representa una respuesta de error en formato JSON.
type ErrorResponse struct {
	// Message contiene el mensaje de error descriptivo
	Message string `json:"message"`
}

// SingUpLoginRequest representa los datos requeridos para registro o autenticación.
type SingUpLoginRequest struct {
	// Email dirección de correo electrónico del usuario
	Email string `json:"email"`
	// Password contraseña en texto plano (se encripta con bcrypt)
	Password string `json:"password"`
}

// SingUpResponse representa la respuesta tras un registro exitoso.
type SingUpResponse struct {
	// ID identificador único generado con KSUID
	ID string `json:"id"`
	// Email dirección de correo del nuevo usuario
	Email string `json:"email"`
}

// LoginResponse representa la respuesta tras una autenticación exitosa.
type LoginResponse struct {
	// Token token JWT firmado para acceso a endpoints protegidos
	Token string `json:"token"`
}

// SendErrorResponse envía una respuesta de error en formato JSON al cliente.
//
// Parámetros:
//   - w *http.ResponseWriter: puntero al ResponseWriter de la respuesta HTTP
//   - message string: mensaje descriptivo del error para mostrar al usuario
//   - status int: código de estado HTTP (ej. 400, 401, 500)
func SendErrorResponse(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

// SingUpHandler maneja el registro de nuevos usuarios.
//
// Ruta: POST /signup
//
// Parámetros:
//   - s server.Server: instancia del servidor para acceso a configuración y repositorios
//
// Retornos:
//   - http.HandlerFunc: manejador que procesa la solicitud de registro
//
// Comportamiento:
//   - Valida el JSON del body (email, password)
//   - Genera ID único con KSUID
//   - Encripta la contraseña con bcrypt (HASH_COST = 12)
//   - Inserta usuario en PostgreSQL
//   - Maneja error de duplicado (status 409 Conflict)
//
// Respuesta exitosa (200 OK):
//
//	{
//	  "id": "uuid-del-nuevo-usuario",
//	  "email": "usuario@email.com"
//	}
func SingUpHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request SingUpLoginRequest

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

		user := models.User{
			Id:       id.String(),
			Email:    request.Email,
			Password: string(hashedPassword),
		}

		err = repository.InsertUser(r.Context(), &user)
		if err != nil {
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: err.Error()})
			return
		}

		response := SingUpResponse{
			ID:    id.String(),
			Email: request.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// LoginHandler maneja la autenticación de usuarios.
//
// Ruta: POST /login
//
// Parámetros:
//   - s server.Server: instancia del servidor para acceso al secret JWT
//
// Retornos:
//   - http.HandlerFunc: manejador que procesa la solicitud de login
//
// Comportamiento:
//   - Valida el JSON del body (email, password)
//   - Busca usuario por email en la base de datos
//   - Compara contraseña con bcrypt
//   - Genera token JWT válido por 24 horas
//
// Respuestas posibles:
//   - 200 OK: {"token": "jwt-token-string"}
//   - 400 Bad Request: payload inválido
//   - 401 Unauthorized: usuario o password incorrectos
//   - 500 Internal Server Error: error de base de datos
func LoginHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request SingUpLoginRequest

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
				// Tiempo de expiración del token (ej. 24 horas)
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				// Tiempo de emisión del token
				IssuedAt: jwt.NewNumericDate(time.Now()),
				// Emisor del token JWT (opcional)
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
		json.NewEncoder(w).Encode(LoginResponse{Token: tokenString})
	}
}

// MeHandler maneja la obtención del perfil del usuario autenticado delegando en NewUserFromToken.
//
// Ruta: GET /me
//
// Parámetros:
//   - s server.Server: instancia del servidor para acceso al secret JWT
//
// Retornos:
//   - http.HandlerFunc: manejador que procesa la solicitud de perfil
//
// Comportamiento:
//   - Extrae y verifica token JWT del header Authorization (Bearer TOKEN)
//   - Utiliza NewUserFromToken para validar el token y obtener el usuario
//   - Devuelve el usuario completo en formato JSON
//
// Respuesta exitosa (200 OK):
//
//	{
//	  "id": "uuid-usuario",
//	  "email": "usuario@email.com",
//	  "password": "$2a$..."
//	}
//
// Errores:
//   - Token inválido o expirado: 401 Unauthorized
//   - Error de DB: 500 Internal Server Error
func MeHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.NewUserFromToken(s, r)
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	}
}
