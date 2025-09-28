package database

import (
	"context"
	"database/sql"
	"log"

	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
	_ "github.com/lib/pq"
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

func (repo *PostgresRepository) InsertUser(ctx context.Context, user *models.User) error {
	_, err := repo.db.ExecContext(ctx, "INSERT INTO users(id, email, password) VALUES ($1,$2,$3)", user.Id, user.Email, user.Password)
	return err
}

func (repo *PostgresRepository) GetUserById(ctx context.Context, id string) (*models.User, error) {
	rowsUsers, err := repo.db.QueryContext(ctx, "SELECT id, email FROM users WHERE id = $1", id)
	defer func() {
		err := rowsUsers.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	var user models.User
	if rowsUsers.Next() {
		err = rowsUsers.Scan(&user.Id, &user.Email)
		if err != nil {
			return &models.User{}, err
		}
	}
	return &user, nil
}

func (repo *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	rowsUsers, err := repo.db.QueryContext(ctx, "SELECT id, email, password FROM users WHERE email = $1", email)
	defer func() {
		err := rowsUsers.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	var user models.User
	if rowsUsers.Next() {
		err = rowsUsers.Scan(&user.Id, &user.Email, &user.Password)
		if err != nil {
			return &models.User{}, err
		}
	}
	return &user, nil
}

func (repo *PostgresRepository) Close() error {
	return repo.db.Close()
}
