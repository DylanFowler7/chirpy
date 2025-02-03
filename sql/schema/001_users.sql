-- +goose Up
CREATE TABLE users (
id UUID primary key,
created_at TIMESTAMP not NULL,
updated_at TIMESTAMP not NULL,
email TEXT UNIQUE not NULL
);

-- +goose Down
DROP TABLE users;