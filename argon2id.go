// Package argon2id provides Argon2ID password hashing with a bcrypt-inspired API.
//
// This package offers a simplified interface for Argon2ID password hashing that
// closely mirrors the golang.org/x/crypto/bcrypt API, making migration between
// bcrypt and Argon2ID straightforward.
//
// Basic usage:
//
//	password := []byte("mySecretPassword")
//	hash, err := argon2id.GenerateFromPassword(password, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	err = argon2id.CompareHashAndPassword(hash, password)
//	if err != nil {
//		log.Fatal("Password doesn't match")
//	}
//
// Custom parameters can be provided for different security requirements:
//
//	params := &argon2id.Params{
//		Time:    4,          // iterations
//		Memory:  128 * 1024, // 128 MB
//		Threads: 4,          // parallelism
//		KeyLen:  32,         // output length
//	}
//	hash, err := argon2id.GenerateFromPassword(password, params)
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default parameters for Argon2ID
// These values provide a good balance between security and performance
// for most web applications.
const (
	DefaultTime    = 3
	DefaultMemory  = 64 * 1024 // 64 MB
	DefaultThreads = 2
	DefaultKeyLen  = 32
	SaltLen        = 16

	// MinHashLength is the minimum expected length of a valid argon2id hash string
	MinHashLength = 30

	// Parameter limits for security and DoS protection
	// These constants can be adjusted for different deployment scenarios:
	// - For high-security environments: increase MaxTime and MaxMemory
	// - For resource-constrained environments: decrease defaults
	// - For testing: use lower values to speed up test execution
	MinTime    = 1           // Argon2 minimum requirement
	MaxTime    = 100         // DoS protection (reasonable upper bound)
	MinMemory  = 8           // Argon2 minimum requirement (8 KB)
	MaxMemory  = 1024 * 1024 // DoS protection (1 GB maximum)
	MinThreads = 1           // Argon2 minimum requirement
	MinKeyLen  = 4           // Security minimum (32-bit minimum)
	MaxKeyLen  = 128         // Practical maximum (no legitimate need for more)
)

var (
	// ErrInvalidHash is returned when the hash format is invalid or malformed.
	ErrInvalidHash = errors.New("argon2id: invalid hash format")

	// ErrIncompatibleVersion is returned when the Argon2 version is not supported.
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version")

	// ErrIncompatibleVariant is returned when the hash uses a different Argon2 variant.
	ErrIncompatibleVariant = errors.New("argon2id: incompatible variant")

	// ErrHashTooShort is returned when the provided hash is too short to be valid.
	ErrHashTooShort = errors.New("argon2id: hash too short")
)

// Params holds the Argon2ID algorithm parameters.
//
// Time controls the number of iterations over the memory.
// Memory controls the size of the memory used (in KB).
// Threads controls the number of threads used for parallelism.
// KeyLen controls the length of the output key in bytes.
type Params struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory usage in KB
	Threads uint8  // Number of threads (1-255)
	KeyLen  uint32 // Output key length in bytes
}

// DefaultParams returns a new Params struct with secure default values.
//
// The defaults are suitable for most web applications and provide
// a good balance between security and performance.
func DefaultParams() *Params {
	return &Params{
		Time:    DefaultTime,
		Memory:  DefaultMemory,
		Threads: DefaultThreads,
		KeyLen:  DefaultKeyLen,
	}
}

// GenerateFromPassword creates an Argon2ID hash from the given password.
//
// The password parameter should be the plaintext password as a byte slice.
// If params is nil, DefaultParams() will be used.
//
// The returned hash is in the standard Argon2 format and can be stored
// directly in a database or other persistent storage.
//
// Each call to GenerateFromPassword with the same password will produce
// a different hash due to the random salt generation.
//
// Parameter validation:
// - Time must be >= 1 and <= 100
// - Memory must be >= 8 KB and <= 1 GB
// - Threads must be >= 1
// - KeyLen must be >= 4 bytes and <= 128 bytes
//
// Returns an error if parameters are outside these bounds.
func GenerateFromPassword(password []byte, params *Params) ([]byte, error) {
	if params == nil {
		params = DefaultParams()
	}

	// Validate parameters
	if params.Time < MinTime || params.Memory < MinMemory || params.Threads < MinThreads || params.KeyLen < MinKeyLen {
		return nil, errors.New("argon2id: invalid parameters")
	}
	if params.Time > MaxTime || params.Memory > MaxMemory || params.KeyLen > MaxKeyLen {
		return nil, errors.New("argon2id: parameters too high")
	}

	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)

	// Format: $argon2id$v=19$m=memory,t=time,p=threads$salt$hash
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s"
	return []byte(fmt.Sprintf(format, params.Memory, params.Time, params.Threads, encodedSalt, encodedHash)), nil
}

// CompareHashAndPassword compares a plaintext password with an Argon2ID hash.
//
// Returns nil if the password matches the hash, otherwise returns an error.
// The comparison is performed in constant time to prevent timing attacks.
//
// The hashedPassword parameter should be a hash previously generated by
// GenerateFromPassword. The password parameter should be the plaintext
// password to verify.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	params, salt, hash, err := decodeHash(string(hashedPassword))
	if err != nil {
		return err
	}

	// Generate hash with same parameters
	computedHash := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)

	// Use constant time comparison
	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return nil
	}

	return errors.New("argon2id: password does not match hash")
}

// ExtractParams extracts the Argon2ID parameters from a hash string.
//
// This function parses an existing hash and returns the parameters
// that were used to generate it. This can be useful for:
//   - Checking if a hash needs to be updated with stronger parameters
//   - Displaying parameter information
//   - Migrating between different parameter sets
//
// The hashedPassword parameter should be a hash generated by this package
// or another compatible Argon2ID implementation.
func ExtractParams(hashedPassword []byte) (*Params, error) {
	params, _, _, err := decodeHash(string(hashedPassword))
	if err != nil {
		return nil, err
	}
	return params, nil
}

// NeedsRehash checks if a hash was generated with weaker parameters than the provided ones.
//
// It compares the time and memory parameters of the hash with the given newParams.
// Returns true if the hash should be rehashed with stronger parameters (higher time or memory).
// This is useful for upgrading hashes to stronger settings over time without breaking
// existing user logins.
//
// The hashedPassword should be a valid Argon2ID hash generated by this package.
// newParams should contain the desired stronger parameters.
//
// Example usage:
//
//	needsRehash, err := argon2id.NeedsRehash(oldHash, strongerParams)
//	if needsRehash {
//	    newHash, err := argon2id.GenerateFromPassword(password, strongerParams)
//	    // Update stored hash
//	}
func NeedsRehash(hashedPassword []byte, newParams *Params) (bool, error) {
	oldParams, err := ExtractParams(hashedPassword)
	if err != nil {
		return false, err
	}
	return oldParams.Time < newParams.Time || oldParams.Memory < newParams.Memory, nil
}

// decodeHash parses an Argon2ID hash string and returns the parameters, salt, and hash
func decodeHash(hash string) (*Params, []byte, []byte, error) {
	if len(hash) < MinHashLength {
		return nil, nil, nil, ErrHashTooShort
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if err := validateVariantAndVersion(parts[1], parts[2]); err != nil {
		return nil, nil, nil, err
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	// Validate lengths
	if len(salt) != SaltLen {
		return nil, nil, nil, ErrInvalidHash
	}
	if len(hashBytes) == 0 {
		return nil, nil, nil, ErrInvalidHash
	}

	// Set key length based on hash length
	params.KeyLen = uint32(len(hashBytes)) // #nosec G115 - len() returns non-negative int, safe conversion

	return params, salt, hashBytes, nil
}

// validateVariantAndVersion checks the algorithm variant and version
func validateVariantAndVersion(variant, version string) error {
	if variant != "argon2id" {
		return ErrIncompatibleVariant
	}

	if version != "v=19" {
		return ErrIncompatibleVersion
	}

	return nil
}

// parseParams parses the parameters section of the hash
func parseParams(paramString string) (*Params, error) {
	params := &Params{}
	paramParts := strings.Split(paramString, ",")
	if len(paramParts) != 3 {
		return nil, ErrInvalidHash
	}

	for _, param := range paramParts {
		if err := parseParam(params, param); err != nil {
			return nil, err
		}
	}

	return params, nil
}

// parseParam parses a single parameter key=value pair
func parseParam(params *Params, param string) error {
	keyValue := strings.Split(param, "=")
	if len(keyValue) != 2 {
		return ErrInvalidHash
	}

	switch keyValue[0] {
	case "m":
		value, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return ErrInvalidHash
		}
		params.Memory = uint32(value)
	case "t":
		value, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return ErrInvalidHash
		}
		params.Time = uint32(value)
	case "p":
		value, err := strconv.ParseUint(keyValue[1], 10, 8)
		if err != nil {
			return ErrInvalidHash
		}
		params.Threads = uint8(value)
	default:
		return ErrInvalidHash
	}

	return nil
}
