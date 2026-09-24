// Package auth contiene funciones genéricas de autenticación reutilizables.
// Proporciona lógica compartida para validar tokens JWT y obtener usuarios.
package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/golang-jwt/jwt/v5"
)

// NewUserFromToken extrae y valida el token JWT del header Authorization,
// decodifica las claims para obtener el userId, y consulta la base de datos
// para obtener el usuario completo asociado.
//
// Parámetros:
//   - s server.Server: instancia del servidor para acceso al secret JWT y repositorio
//   - r *http.Request: solicitud HTTP que contiene el header Authorization
//
// Retornos:
//   - (*models.User, error): puntero al usuario encontrado o nil si no es válido
//
// Comportamiento:
//   - Extrae token del header "Authorization" (debe empezar con "Bearer ")
//   - Valida y decodifica el token JWT con el secret configurado
//   - Obtiene userId de las claims del token
//   - Consulta la base de datos para obtener los datos completos del usuario
//
// Errores:
//   - Token inválido, expirado o malformado: error no nil (usuario == nil)
//   - Error de base de datos al obtener el usuario: error no nil (usuario == nil)
func NewUserFromToken(s server.Server, r *http.Request) (*models.User, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))

	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header: missing or invalid 'Bearer' prefix")
	}

	tokenString := strings.TrimPrefix(authorization, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &models.AppClaims{},
		func(token *jwt.Token) (any, error) {
			return []byte(s.Config().JwtSecret), nil
		})

	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	if claims, ok := token.Claims.(*models.AppClaims); ok && token.Valid {
		user, err := repository.GetUserById(r.Context(), claims.UserId)
		if err != nil {
			return nil, fmt.Errorf("error obtaining user from database: %w", err)
		}

		return user, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}
