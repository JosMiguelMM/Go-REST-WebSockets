----- Define la estructura de la tabla de publicaciones con una relación de clave foránea hacia la tabla de usuarios.
CREATE TABLE posts
(
    id           UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    post_content VARCHAR   NOT NULL,
    user_id      UUID      NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
