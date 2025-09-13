package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/JosMiguelMM/Go-REST-WebSockets/handlers"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func BinderRoutes(s server.Server, r *mux.Router) {
	r.HandleFunc("/", handlers.HomeHandler(s)).Methods(http.MethodGet)
}

func main() {
	ctx := context.Background()
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error al cargar variables de entorno")
	}

	PORT := os.Getenv("PORT")
	JWT_SECRET := os.Getenv("JWT_SECRET")
	DATABASE_URL := os.Getenv("DATABASE_URL")

	// imprimir variables de entorno
	println("PORT:", PORT)

	s, err := server.NewServer(ctx, &server.Config{
		JwtSecret:   JWT_SECRET,
		Port:        PORT,
		DataBaseUrl: DATABASE_URL,
	})

	if err != nil {
		log.Fatal(err)
	}

	s.Start(BinderRoutes)
}
