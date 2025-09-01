package main

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/sixcolors/argon2id"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in our system
type User struct {
	Email    string
	Password string // This would be the hashed password in a real system
	ID       int
}

// MigrationUserStore demonstrates automatic migration from bcrypt to argon2id
type MigrationUserStore struct {
	mu     sync.RWMutex
	users  map[string]*User
	nextID int
}

func NewMigrationUserStore() *MigrationUserStore {
	return &MigrationUserStore{
		users:  make(map[string]*User),
		nextID: 1,
	}
}

// isBcryptHash checks if a hash is in bcrypt format
func isBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

// CreateUserWithBcrypt creates a user with a bcrypt hash (simulating legacy users)
func (s *MigrationUserStore) CreateUserWithBcrypt(email, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		return fmt.Errorf("user already exists")
	}

	// Hash password with bcrypt (simulating legacy system)
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	s.users[email] = &User{
		Email:    email,
		Password: string(bcryptHash),
		ID:       s.nextID,
	}
	s.nextID++

	log.Printf("✅ Created user with bcrypt: %s", email)
	return nil
}

// CreateUserWithArgon2id creates a user with argon2id hash
func (s *MigrationUserStore) CreateUserWithArgon2id(email, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		return fmt.Errorf("user already exists")
	}

	// Hash password with argon2id
	argon2idHash, err := argon2id.GenerateFromPassword([]byte(password), nil)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	s.users[email] = &User{
		Email:    email,
		Password: string(argon2idHash),
		ID:       s.nextID,
	}
	s.nextID++

	log.Printf("✅ Created user with argon2id: %s", email)
	return nil
}

// Login authenticates a user and automatically migrates bcrypt hashes to argon2id
func (s *MigrationUserStore) Login(email, password string) (*User, error) {
	s.mu.RLock()
	user, exists := s.users[email]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	hash := user.Password

	// Check hash type and verify password
	if isBcryptHash(hash) {
		// Legacy bcrypt hash - verify with bcrypt
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			log.Printf("❌ Bcrypt login failed for %s", email)
			return nil, fmt.Errorf("invalid credentials")
		}

		log.Printf("✅ Bcrypt login successful for %s - migrating to argon2id", email)

		// Password is correct, migrate to argon2id
		return s.migrateUserToArgon2id(user, password)

	} else {
		// Modern argon2id hash - verify with argon2id
		err := argon2id.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			log.Printf("❌ Argon2id login failed for %s", email)
			return nil, fmt.Errorf("invalid credentials")
		}

		log.Printf("✅ Argon2id login successful for %s", email)

		// Check if we should upgrade parameters
		return s.checkAndUpgradeHash(user, password)
	}
}

// migrateUserToArgon2id migrates a user from bcrypt to argon2id
func (s *MigrationUserStore) migrateUserToArgon2id(user *User, password string) (*User, error) {
	// Generate new argon2id hash
	newHash, err := argon2id.GenerateFromPassword([]byte(password), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate hash: %w", err)
	}

	// Update user in store with proper synchronization
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check the hash hasn't changed (prevent double migration)
	if !isBcryptHash(user.Password) {
		log.Printf("⚠️  User %s already migrated, skipping", user.Email)
		return user, nil
	}

	user.Password = string(newHash)

	log.Printf("🔄 Migrated %s from bcrypt to argon2id", user.Email)
	return user, nil
}

// checkAndUpgradeHash checks if the current argon2id hash needs parameter upgrade
func (s *MigrationUserStore) checkAndUpgradeHash(user *User, password string) (*User, error) {
	// Define stronger parameters for future upgrades
	strongerParams := &argon2id.Params{
		Time:    6,          // More iterations than default (3)
		Memory:  128 * 1024, // More memory than default (64*1024)
		Threads: 4,          // More threads than default (2)
		KeyLen:  32,
	}

	// Check if rehash is needed
	needsRehash, err := argon2id.NeedsRehash([]byte(user.Password), strongerParams)
	if err != nil {
		// If we can't check, just return the user (don't fail login)
		log.Printf("⚠️  Could not check rehash for %s: %v", user.Email, err)
		return user, nil
	}

	if needsRehash {
		log.Printf("🔄 Upgrading hash parameters for %s", user.Email)

		// Generate new hash with stronger parameters
		newHash, err := argon2id.GenerateFromPassword([]byte(password), strongerParams)
		if err != nil {
			// If upgrade fails, just return the user (don't fail login)
			log.Printf("⚠️  Could not upgrade hash for %s: %v", user.Email, err)
			return user, nil
		}

		// Update user in store with proper synchronization
		s.mu.Lock()
		defer s.mu.Unlock()

		// Double-check the hash still needs upgrading (prevent race conditions)
		currentNeedsRehash, err := argon2id.NeedsRehash([]byte(user.Password), strongerParams)
		if err != nil || !currentNeedsRehash {
			log.Printf("⚠️  Hash for %s already upgraded or changed, skipping", user.Email)
			return user, nil
		}

		user.Password = string(newHash)

		log.Printf("✅ Upgraded hash parameters for %s", user.Email)
	}

	return user, nil
}

// GetUser returns a user (for inspection)
func (s *MigrationUserStore) GetUser(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[email]
	return user, exists
}

func main() {
	fmt.Println("=== Argon2ID Migration Example ===")
	fmt.Println("Demonstrating automatic migration from bcrypt to argon2id")
	fmt.Println()

	store := NewMigrationUserStore()

	// Create some users with different hash types
	fmt.Println("1. Creating users with different hash types:")

	// Legacy user with bcrypt
	err := store.CreateUserWithBcrypt("legacy@example.com", "password123")
	if err != nil {
		log.Fatal("Failed to create legacy user:", err)
	}

	// Modern user with argon2id
	err = store.CreateUserWithArgon2id("modern@example.com", "password123")
	if err != nil {
		log.Fatal("Failed to create modern user:", err)
	}

	fmt.Println()

	// Demonstrate login and automatic migration
	fmt.Println("2. Logging in users (triggers automatic migration):")

	// Login legacy user (should migrate from bcrypt to argon2id)
	fmt.Println("   Logging in legacy user...")
	user1, err := store.Login("legacy@example.com", "password123")
	if err != nil {
		log.Fatal("Login failed:", err)
	}
	fmt.Printf("   ✅ Legacy user logged in: %s (ID: %d)\n", user1.Email, user1.ID)

	// Check if hash was migrated
	if user, exists := store.GetUser("legacy@example.com"); exists {
		if !isBcryptHash(user.Password) {
			fmt.Println("   🔄 Hash successfully migrated to argon2id!")
		}
	}

	// Login modern user (should check for parameter upgrades)
	fmt.Println("   Logging in modern user...")
	user2, err := store.Login("modern@example.com", "password123")
	if err != nil {
		log.Fatal("Login failed:", err)
	}
	fmt.Printf("   ✅ Modern user logged in: %s (ID: %d)\n", user2.Email, user2.ID)

	fmt.Println()

	// Demonstrate failed login
	fmt.Println("3. Testing failed login:")
	_, err = store.Login("legacy@example.com", "wrongpassword")
	if err != nil {
		fmt.Println("   ✅ Correctly rejected wrong password")
	}

	fmt.Println()

	// Show hash information
	fmt.Println("4. Hash information:")
	for email := range store.users {
		if user, exists := store.GetUser(email); exists {
			hashType := "argon2id"
			if isBcryptHash(user.Password) {
				hashType = "bcrypt"
			}
			fmt.Printf("   %s: %s hash\n", email, hashType)
		}
	}

	fmt.Println()
	fmt.Println("=== Migration Example Complete ===")
	fmt.Println("This example shows how to:")
	fmt.Println("• Detect bcrypt vs argon2id hashes")
	fmt.Println("• Verify passwords with the appropriate algorithm")
	fmt.Println("• Automatically migrate users during login")
	fmt.Println("• Upgrade hash parameters for existing argon2id users")
}
