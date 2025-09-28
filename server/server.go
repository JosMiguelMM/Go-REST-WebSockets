package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/JosMiguelMM/Go-REST-WebSockets/database"
	repository "github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/gorilla/mux"
)

type Config struct {
	Port        string
	JwtSecret   string
	DataBaseUrl string
}

type Server interface {
	Config() *Config
}

type Broker struct {
	config *Config
	router *mux.Router
}

func (b *Broker) Config() *Config {
	return b.config
}

func NewServer(ctx context.Context, config *Config) (*Broker, error) {
	switch {
	case config.Port == "":
		return nil, errors.New("Port is required")
	case config.JwtSecret == "":
		return nil, errors.New("JwtSecret is required")
	case config.DataBaseUrl == "":
		return nil, errors.New("DataBaseUrl is required")
	}

	broker := &Broker{
		config: config,
		router: mux.NewRouter(),
	}
	return broker, nil
}

func (broker *Broker) Start(binder func(s Server, r *mux.Router)) {
	broker.router = mux.NewRouter()
	binder(broker, broker.router)
	repo, err := database.NewPostgres(broker.config.DataBaseUrl)
	if err != nil {
		log.Fatal("Error creating database repository:", err)
	}
	repository.SetRepository(repo)
	log.Println("Starting server on port ", broker.Config().Port)
	if err := http.ListenAndServe(":"+broker.config.Port, broker.router); err != nil {
		log.Fatal("ListendAndServer ", err)
	}
}
