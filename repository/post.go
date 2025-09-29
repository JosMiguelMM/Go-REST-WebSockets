package repository

import (
	"context"

	"github.com/JosMiguelMM/Go-REST-WebSockets/models"
)

type PostRepository interface {
	InsertPost(ctx context.Context, post *models.Post) error
	Close() error
}

var implementationPostRepository PostRepository

func InsertPost(ctx context.Context, post *models.Post) error {
	return implementationPostRepository.InsertPost(ctx, post)
}

func ClosePostRepository() error {
	return implementationPostRepository.Close()
}
