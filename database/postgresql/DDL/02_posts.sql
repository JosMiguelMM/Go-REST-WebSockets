----- Define la estructura de la tabla de publicaciones con una relación de clave foránea hacia la tabla de usuarios.
CREATE TABLE posts
(
    id           VARCHAR(32) PRIMARY KEY NOT NULL,
    post_content VARCHAR                 NOT NULL,
    user_id      VARCHAR(32)             NOT NULL,
    created_at   TIMESTAMP               NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
