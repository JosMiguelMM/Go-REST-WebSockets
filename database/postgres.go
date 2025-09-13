package postgres

import (
	"context"
	"database/sql"

	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgres(url string) (*PostgresRepository, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	return &PostgresRepository{db: db}, nil
}

func (repo *PostgresRepository) InsertUser(ctx context.Context, user models.User) error {
	_, err := repo.db.ExecContext(ctx, "INSERT INTO users(email, password) VALUES ($1,$2)", user.Email, user.Password)
	return err
}
