package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	// Create a test user ID
	userID := uuid.New()

	// Create a test secret
	secret := "532079fyq3092uyf"

	// Test valid token creation
	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("Error creating token: %v", err)
	}
	if token == "" {
		t.Fatal("Expected token to be non-empty")
	}

	// Test valid token validation
	extractedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("Error validating token: %v", err)
	}
	if extractedID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, extractedID)
	}
}

func TestExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "6829432"

	// Create a token that expires in 1 nanosecond
	token, _ := MakeJWT(userID, secret, time.Nanosecond)

	// Wait a bit to ensure token expires
	time.Sleep(time.Millisecond)

	// Now try to validate the expired token
	_, err := ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestInvalidSecret(t *testing.T) {
	userID := uuid.New()
	secret := "32643632"
	wrongSecret := "864565"

	// Create token with correct secret
	token, _ := MakeJWT(userID, secret, time.Hour)

	// Try to validate with wrong secret
	_, err := ValidateJWT(token, wrongSecret)

	// What should we expect here?
	if err == nil {
		t.Fatal("Expected error for invalid secret, got nil")
	}
}

func TestMalformedToken(t *testing.T) {
	secret := "test-secret"

	// Try some malformed tokens
	malformedTokens := []string{
		"",              // empty token
		"not.even.jwt",  // looks like JWT but isn't
		"invalid.token", // incomplete segments
		"abc",           // random string
	}

	for _, token := range malformedTokens {
		_, err := ValidateJWT(token, secret)
		if err == nil {
			t.Errorf("Expected error for malformed token '%s', got nil", token)
		}
	}
}
