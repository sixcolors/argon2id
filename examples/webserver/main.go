// Example Webserver application using Argon2ID for password hashing
//
// This example demonstrates user registration and login with secure password storage
// using Argon2ID.
//
// This code is for educational purposes and should not be used in production without proper security measures.
// It does not include protection against timing attacks, rate limiting, or other security best practices.
//
// As it is intended for educational purposes, it also exposes the Argon2ID parameters used for hashing,
// which should not be done in production code.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/sixcolors/argon2id"
)

// User represents a user account
type User struct {
	Email        string `json:"email"`
	PasswordHash []byte `json:"-"` // Never include in JSON responses
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Response represents an API response
type Response struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// Simple in-memory user store (use a real database in production)
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

func (s *UserStore) CreateUser(email string, passwordHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		return fmt.Errorf("user already exists")
	}

	s.users[email] = &User{
		Email:        email,
		PasswordHash: passwordHash,
	}
	return nil
}

func (s *UserStore) GetUser(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[email]
	return user, exists
}

var userStore = NewUserStore()

// Custom Argon2ID parameters for this application
var appParams = &argon2id.Params{
	Time:    3,         // 3 iterations
	Memory:  64 * 1024, // 64 MB
	Threads: 2,         // 2 threads
	KeyLen:  32,        // 32-byte output
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, Response{Error: "Invalid JSON"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSONResponse(w, http.StatusBadRequest, Response{Error: "Email and password required"})
		return
	}

	// Hash the password
	passwordHash, err := argon2id.GenerateFromPassword([]byte(req.Password), appParams)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		writeJSONResponse(w, http.StatusInternalServerError, Response{Error: "Failed to create user"})
		return
	}

	// Store the user
	err = userStore.CreateUser(req.Email, passwordHash)
	if err != nil {
		writeJSONResponse(w, http.StatusConflict, Response{Error: err.Error()})
		return
	}

	log.Printf("User registered: %s", req.Email)
	writeJSONResponse(w, http.StatusCreated, Response{Message: "User created successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, Response{Error: "Invalid JSON"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSONResponse(w, http.StatusBadRequest, Response{Error: "Email and password required"})
		return
	}

	// Get user from store
	user, exists := userStore.GetUser(req.Email)
	if !exists {
		writeJSONResponse(w, http.StatusUnauthorized, Response{Error: "Invalid credentials"})
		return
	}

	// Compare password with hash
	err := argon2id.CompareHashAndPassword(user.PasswordHash, []byte(req.Password))
	if err != nil {
		log.Printf("Login failed for %s: %v", req.Email, err)
		writeJSONResponse(w, http.StatusUnauthorized, Response{Error: "Invalid credentials"})
		return
	}

	log.Printf("User logged in: %s", req.Email)
	writeJSONResponse(w, http.StatusOK, Response{Message: "Login successful"})
}

func writeJSONResponse(w http.ResponseWriter, status int, response Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func main() {
	fmt.Println("=== Argon2ID Web Server Example ===")
	fmt.Printf("Using Argon2ID parameters:\n")
	fmt.Printf("  Time: %d\n", appParams.Time)
	fmt.Printf("  Memory: %d KB\n", appParams.Memory)
	fmt.Printf("  Threads: %d\n", appParams.Threads)
	fmt.Printf("  Key Length: %d bytes\n", appParams.KeyLen)
	fmt.Println()

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server starting on :8080")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /register - Register a new user")
	fmt.Println("  POST /login    - Login with credentials")
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Println(`  curl -X POST http://localhost:8080/register \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"mypassword"}'`)
	fmt.Println()
	fmt.Println(`  curl -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"mypassword"}'`)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
