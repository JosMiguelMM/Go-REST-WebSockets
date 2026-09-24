package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/JosMiguelMM/Go-REST-WebSockets/auth"
	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
)

type InsertPostRequest struct {
	Content string `json:"content"`
}

type InsertPostResponse struct {
	Id      string `json:"id"`
	Content string `json:"content"`
}

// No cambiamos esto ya que el ID viene de la tabla

func InsertPostHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.NewUserFromToken(s, r)
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		var postRequest = InsertPostRequest{}
		if err := json.NewDecoder(r.Body).Decode(&postRequest); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		post := models.Post{
			Content: postRequest.Content,
			UserId:  user.Id,
		}
		err = repository.InsertPost(r.Context(), &post)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(InsertPostResponse{
			Id:      post.UserId,
			Content: post.Content,
		})
	}
}
