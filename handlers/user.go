package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/segmentio/ksuid"
)

type SingUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SingUpResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func SingUpHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request = SingUpRequest{}
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
		var response SingUpResponse = SingUpResponse{
			ID:    id.String(),
			Email: request.Email,
		}
		json.NewEncoder(w).Encode(response)
	}
}
