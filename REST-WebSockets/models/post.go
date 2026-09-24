package models

type Post struct {
	Content string `json:"content"`
	UserId  string `json:"user_id"`
}
