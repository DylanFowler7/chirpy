-- name: CreateChirp :one
INSERT INTO chirp (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetChirp :one
SELECT * FROM chirp
WHERE id = $1
LIMIT 1;

-- name: GetChirps :many
SELECT * FROM chirp
ORDER BY created_at ASC NULLS FIRST;

-- name: GetAuthorChirps :many
SELECT * FROM chirp
WHERE user_id = $1
ORDER BY created_at ASC NULLS FIRST;

-- name: DeleteChirp :exec
DELETE FROM chirp
WHERE id = $1;