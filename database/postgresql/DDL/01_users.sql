----- Define la estructura de la tabla de usuarios para almacenar credenciales e información de cuenta.
CREATE TABLE users
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) UNIQUE     NOT NULL,
    password   VARCHAR(255)            NOT NULL,
    created_at TIMESTAMP               NOT NULL DEFAULT NOW()
);
