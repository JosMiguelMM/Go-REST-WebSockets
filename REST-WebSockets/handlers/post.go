package handlers

import (
	"encoding/json"
	"net/http"
	"uuid"

	"github.com/JosMiguelMM/Go-REST-WebSockets/auth"
	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	"github.com/JosMiguelMM/Go-REST-WebSockets/repository"
	"github.com/JosMiguelMM/Go-REST-WebSockets/server"
	"github.com/gorilla/mux"
)

type UpsertPostRequest struct {
	Content string `json:"content"`
}

type InsertPostResponse struct {
	Id      string `json:"id"`
	Content string `json:"content"`
}

type UpsertPostResponse struct {
	Message string `json:"message"`
}

func InsertPostHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.NewUserFromToken(s, r)
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		var postRequest = UpsertPostRequest{}
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

func GetPostByIdHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := auth.NewUserFromToken(s, r)
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		post, err := repository.GetPostById(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(post)
	}
}

func UpdatePostHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.NewUserFromToken(s, r)
		if err != nil {
			SendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		var upsertPostRequest = UpsertPostRequest{}
		if err := json.NewDecoder(r.Body).Decode(&upsertPostRequest); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		params := mux.Vars(r)
		id := params["id"]
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		_, err = uuid.Parse(id)
		if err != nil {
			SendErrorResponse(w, "Invalid ID format", http.StatusBadRequest)
			return
		}
		post := models.Post{
			Id:      id,
			UserId:  user.Id,
			Content: upsertPostRequest.Content,
		}
		err = repository.UpdatePost(r.Context(), &post)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UpsertPostResponse{
			Message: "Post updated successfully",
		})
	}
}
