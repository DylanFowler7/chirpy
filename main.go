package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)
	defer db.Close()
	apiCfg := &apiConfig{
		database: dbQueries,
		secret:   os.Getenv("SECRET"),
		polkaKey: os.Getenv("POLKA_KEY"),
	}
	fileServer := http.FileServer(http.Dir("."))
	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fileServer)))
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.handler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirp)
	serveMux.HandleFunc("POST /api/users", apiCfg.handlerCreateUser)
	serveMux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	serveMux.HandleFunc("PUT /api/users", apiCfg.handlerUpdate)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDelete)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerChirpyRed)
	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})
	err = http.ListenAndServe(":8080", serveMux)
	if err != nil {
		log.Fatal(err)
	}
}

type apiConfig struct {
	fileserverHits atomic.Int32
	database       *database.Queries
	secret         string
	polkaKey       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	err := cfg.database.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("Error deleting users: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

type errorResponse struct {
	Error string `json:"error"`
}

type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type chirpResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"-"`
	CreatedAtStr string    `json:"created_at"`
	UpdatedAt    time.Time `json:"-"`
	UpdatedAtStr string    `json:"updated_at"`
	Body         string    `json:"body"`
	UserID       uuid.UUID `json:"user_id"`
}

func (apiCfg *apiConfig) handler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	userToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error retrieving token: %s", err)
		w.WriteHeader(401)
		return
	}
	userID, err := auth.ValidateJWT(userToken, apiCfg.secret)
	if err != nil {
		log.Printf("Error retrieving token: %s", err)
		w.WriteHeader(401)
		return
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters %s", err)
		w.WriteHeader(500)
		return
	}
	if len(params.Body) > 140 {
		errResp := errorResponse{
			Error: "Chirp is too long",
		}
		dat, err := json.Marshal(errResp)
		if err != nil {
			log.Printf("Error marshalling json: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return
	}
	if params.Body == "" {
		errResp := errorResponse{
			Error: "Data cannot be empty",
		}
		dat, err := json.Marshal(errResp)
		if err != nil {
			log.Printf("Error marshalling json: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return
	}
	cleanedText := censor(params.Body)
	if cleanedText == "" {
		log.Printf("Error: Chirp body becomes empty after censoring")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(errorResponse{Error: "Invalid chirp body"})
		return
	}
	newChirp, err := apiCfg.database.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedText,
		UserID: userID,
	})
	if err != nil {
		log.Printf("Error retrieving chirp: %s", err)
		w.WriteHeader(500)
		return
	}
	response := chirpResponse{
		ID:           newChirp.ID,
		CreatedAt:    newChirp.CreatedAt,
		CreatedAtStr: newChirp.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    newChirp.UpdatedAt,
		UpdatedAtStr: newChirp.UpdatedAt.Format(time.RFC3339),
		Body:         newChirp.Body,
		UserID:       newChirp.UserID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		w.WriteHeader(500)
	}
}

func (apiCfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		HashedPassword string `json:"password"`
		Email          string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters %s", err)
		w.WriteHeader(500)
		return
	}
	hashedPassword, err := auth.HashPassword(params.HashedPassword) // Correctly hash the password
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server error"})
		return
	}
	newUser, err := apiCfg.database.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error retrieving user: %s", err)
		w.WriteHeader(400)
		return
	}
	user := User{
		ID:        newUser.ID.String(),
		CreatedAt: newUser.CreatedAt,
		UpdatedAt: newUser.UpdatedAt,
		Email:     newUser.Email,
	}
	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling json: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)
}

func (apiCfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	responses := []chirpResponse{}
	s := r.URL.Query().Get("author_id")
	arrange := r.URL.Query().Get("sort")
	if s != "" {
		userID, err := uuid.Parse(s)
		if err != nil {
			log.Printf("could not convert string: %s", err)
			w.WriteHeader(400)
			return
		}
		authorChirps, err := apiCfg.database.GetAuthorChirps(r.Context(), userID)
		if err != nil {
			log.Printf("Error retrieving chirps: %s", err)
			w.WriteHeader(500)
			return
		}
		for _, dbChirp := range authorChirps {
			responseChirp := chirpResponse{
				ID:           dbChirp.ID,
				CreatedAt:    dbChirp.CreatedAt,
				CreatedAtStr: dbChirp.CreatedAt.Format(time.RFC3339),
				UpdatedAt:    dbChirp.UpdatedAt,
				UpdatedAtStr: dbChirp.UpdatedAt.Format(time.RFC3339),
				Body:         dbChirp.Body,
				UserID:       dbChirp.UserID,
			}
			responses = append(responses, responseChirp)
		}
		if arrange == "desc" {
			sort.Slice(responses, func(i int, j int) bool {
				return responses[i].CreatedAt.After(responses[j].CreatedAt)
			})
		} else {
			sort.Slice(responses, func(i int, j int) bool {
				return responses[i].CreatedAt.Before(responses[j].CreatedAt)
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(responses)
		return
	}
	chirps, err := apiCfg.database.GetChirps(r.Context())
	if err != nil {
		log.Printf("Error retrieving chirp: %s", err)
		w.WriteHeader(500)
		return
	}
	for _, dbChirp := range chirps {
		responseChirp := chirpResponse{
			ID:           dbChirp.ID,
			CreatedAt:    dbChirp.CreatedAt,
			CreatedAtStr: dbChirp.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    dbChirp.UpdatedAt,
			UpdatedAtStr: dbChirp.UpdatedAt.Format(time.RFC3339),
			Body:         dbChirp.Body,
			UserID:       dbChirp.UserID,
		}
		responses = append(responses, responseChirp)
	}
	if arrange == "desc" {
		sort.Slice(responses, func(i int, j int) bool {
			return responses[i].CreatedAt.After(responses[j].CreatedAt)
		})
	} else {
		sort.Slice(responses, func(i int, j int) bool {
			return responses[i].CreatedAt.Before(responses[j].CreatedAt)
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(responses)
}

func (apiCfg *apiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirps, err := apiCfg.database.GetChirp(r.Context(), chirpID)
	if err != nil {
		log.Printf("Chirp not found: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		return
	}
	response := chirpResponse{
		ID:           chirps.ID,
		CreatedAt:    chirps.CreatedAt,
		CreatedAtStr: chirps.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    chirps.UpdatedAt,
		UpdatedAtStr: chirps.UpdatedAt.Format(time.RFC3339),
		Body:         chirps.Body,
		UserID:       chirps.UserID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(response)
}

func (apiCfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters %s", err)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}
	user, err := apiCfg.database.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		log.Printf("Error fetching user: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect email or password"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(params.Password))
	if err != nil {
		log.Printf("Unauthorized access %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	type sanitizedUser struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
	}
	token, err := auth.MakeJWT(user.ID, apiCfg.secret, 1*time.Hour)
	if err != nil {
		log.Printf("Error creating JWT: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error creating refresh token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
		return
	}
	refresh := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		RevokedAt: sql.NullTime{Valid: false},
	}
	log.Printf("Created new refresh token for user %s, expires at: %v", user.ID, refresh.ExpiresAt)
	_, err = apiCfg.database.CreateRefreshToken(r.Context(), refresh)
	if err != nil {
		log.Printf("Error storing refresh token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
		return
	}
	User := sanitizedUser{
		ID:           user.ID.String(),
		CreatedAt:    user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    user.UpdatedAt.Format(time.RFC3339),
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(User)
}

func (apiCfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	fmt.Println(">>> Refresh endpoint hit")
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error retrieving token: %s", err)
		w.WriteHeader(401)
		return
	}
	log.Printf("Attempting to refresh with token: %s", refreshToken)
	user, err := apiCfg.database.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No valid refresh token found in database")
		} else {
			log.Printf("Database error when looking up refresh token: %s", err)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("Successfully found user %s for refresh token", user.ID)
	newToken, err := auth.MakeJWT(user.ID, apiCfg.secret, time.Hour)
	if err != nil {
		log.Printf("Error creating token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": newToken,
	})
}

func (apiCfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	fmt.Println(">>> Revoke endpoint hit")
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error retrieving token: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("Attempting to revoke token: %s", refreshToken)
	err = apiCfg.database.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Error revoking token: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("Found token, attempting to revoke")
	err = apiCfg.database.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Error revoking token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("Successfully revoked token")
	w.WriteHeader(http.StatusNoContent)
}

func (apiCfg *apiConfig) handlerUpdate(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	type userResponse struct {
		ID    uuid.UUID `json:"id"`
		Email string    `json:"email"`
	}
	var body requestBody
	headers := r.Header
	ctx := r.Context()
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "error decoding request body",
		})
		return
	}
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "missing auth header",
		})
		return
	}
	const prefixBearer = "Bearer "
	if !strings.HasPrefix(authHeader, prefixBearer) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid auth header format",
		})
		return
	}
	token := strings.TrimPrefix(authHeader, prefixBearer)
	if body.Password == "" && body.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "email or password required",
		})
		return
	}
	var hashedPassword string
	if body.Password != "" {
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errorResponse{
				Error: "error hashing password",
			})
			return
		}
		hashedPassword = hash
	}
	userID, err := auth.ValidateJWT(token, apiCfg.secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid token",
		})
		return
	}
	updatedUser, err := apiCfg.database.UpdateUser(ctx, database.UpdateUserParams{
		ID:             userID,
		Email:          body.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid authentication",
		})
		return
	}
	responseUser := userResponse{
		ID:    updatedUser.ID,
		Email: updatedUser.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseUser)
}

func (apiCfg *apiConfig) handlerDelete(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	headers := r.Header
	authHeader, err := auth.GetAPIKey(headers)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "missing auth header",
		})
		return
	}
	const prefixBearer = "Bearer "
	if !strings.HasPrefix(authHeader, prefixBearer) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid auth header format",
		})
		return
	}
	token := strings.TrimPrefix(authHeader, prefixBearer)
	chirp, err := apiCfg.database.GetChirp(r.Context(), chirpID)
	if err != nil {
		log.Printf("Chirp not found: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	userID, err := auth.ValidateJWT(token, apiCfg.secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid token",
		})
		return
	}
	if userID != chirp.UserID {
		log.Printf("Incorrect user for deletion: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	err = apiCfg.database.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(204)
}

func (apiCfg *apiConfig) handlerChirpyRed(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}
	var body requestBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "error decoding request body",
		})
		return
	}
	if body.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	headers := r.Header
	apiKey, err := auth.GetAPIKey(headers)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			Error: err.Error(),
		})
		return
	}
	if apiKey != apiCfg.polkaKey {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "invalid ApiKey",
		})
		return
	}
	_, err = apiCfg.database.MakeChirpyRed(r.Context(), body.Data.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(errorResponse{
				Error: "user not found",
			})
			return
		}
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "error upgrading account",
		})
		return
	}
	w.WriteHeader(204)
}

func censor(text string) string {
	words := strings.Split(text, " ")
	for i := 0; i < len(words); i++ {
		word := strings.ToLower(words[i])
		if word == "kerfuffle" || word == "sharbert" || word == "fornax" {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}
