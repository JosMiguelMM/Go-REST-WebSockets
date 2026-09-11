// Package handlers contiene los manejadores de rutas HTTP para la API REST.
// Proporciona endpoints para autenticación, perfil de usuario y operaciones básicas.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
)

// HomeResponse representa la respuesta del endpoint de bienvenida.
type HomeResponse struct {
	// Message mensaje de saludo para el cliente
	Message string `json:"message"`
	// Status indica si la API está operativa
	Status bool `json:"status"`
}

// HomeHandler maneja el endpoint de bienvenida/health check.
//
// Ruta: GET /
//
// Parámetros:
//   - s server.Server: instancia del servidor (no se usa en esta implementación)
//
// Retornos:
//   - http.HandlerFunc: manejador que procesa solicitudes GET al root
//
// Comportamiento:
//   - Retorna respuesta JSON simple con estado de bienvenida
//   - No requiere autenticación
//
// Respuesta (200 OK):
//
//	{
//	  "message": "Welcome to the Go REST WebSockets API",
//	  "status": true
//	}
func HomeHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Welcome to the Go REST WebSockets API",
			Status:  true,
		})
	}
}
