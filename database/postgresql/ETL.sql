CREATE TABLE users
(
    id         VARCHAR(32) PRIMARY KEY NOT NULL,
    email      VARCHAR(255) UNIQUE     NOT NULL,
    password   VARCHAR(255)            NOT NULL,
    created_at TIMESTAMP               NOT NULL DEFAULT NOW()
);

CREATE TABLE posts
(
    id           VARCHAR(32) PRIMARY KEY NOT NULL,
    post_content VARCHAR                 NOT NULL,
    user_id      VARCHAR(32)             NOT NULL,
    created_at   TIMESTAMP               NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

