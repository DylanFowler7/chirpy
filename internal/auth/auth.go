package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

type ClaimStruct struct {
	jwt.RegisteredClaims
	ID uuid.UUID `json:"id"`
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := ClaimStruct{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			Subject:   userID.String(),
		},
		ID: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return ss, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&ClaimStruct{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse token: %v", err)
	}
	if claims, ok := token.Claims.(*ClaimStruct); ok && token.Valid {
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			return uuid.Nil, fmt.Errorf("invalid user ID in token: %v", err)
		}
		return userID, nil
	} else {
		return uuid.Nil, fmt.Errorf("invalid token claims")
	}
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		err := fmt.Errorf("error Authorizing token")
		return "", err
	} else if !strings.HasPrefix(authHeader, "Bearer") {
		err := fmt.Errorf("incorrect header")
		return "", err
	} else {
		bearerless := strings.TrimPrefix(authHeader, "Bearer")
		spaceless := strings.TrimPrefix(bearerless, " ")
		return spaceless, nil
	}
}

func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	hex := hex.EncodeToString(bytes)
	return hex, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		err := fmt.Errorf("missing auth header")
		return "", err
	} else if !strings.HasPrefix(authHeader, "ApiKey ") {
		err := fmt.Errorf("invalid auth header format")
		return "", err
	} else {
		bearerless := strings.TrimPrefix(authHeader, "ApiKey ")
		return bearerless, nil
	}
}
