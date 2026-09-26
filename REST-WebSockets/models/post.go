package models

type Post struct {
	Content string `json:"content"`
	UserId  string `json:"user_id"`
	Id      string `json:"id"`
}

type ObtenerPost struct {
	Id        string `json:"id"`
	Content   string `json:"content"`
	UserId    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
}
