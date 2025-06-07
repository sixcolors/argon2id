package main

import (
	"fmt"
	"log"

	"github.com/sixcolors/argon2id"
)

func main() {
	fmt.Println("=== Argon2ID Basic Example ===")

	// Example 1: Basic usage with default parameters
	fmt.Println("1. Basic usage with default parameters:")
	password := []byte("mySecretPassword123!")

	hash, err := argon2id.GenerateFromPassword(password, nil)
	if err != nil {
		log.Fatal("Failed to generate hash:", err)
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Hash: %s\n", hash)

	// Verify the password
	err = argon2id.CompareHashAndPassword(hash, password)
	if err != nil {
		log.Fatal("Password verification failed:", err)
	}
	fmt.Println("✓ Password verification successful!")

	// Example 2: Custom parameters for higher security
	fmt.Println("2. Custom parameters for higher security:")
	customParams := &argon2id.Params{
		Time:    4,          // More iterations
		Memory:  128 * 1024, // 128 MB memory
		Threads: 4,          // More parallelism
		KeyLen:  32,         // 32-byte output
	}

	strongHash, err := argon2id.GenerateFromPassword(password, customParams)
	if err != nil {
		log.Fatal("Failed to generate strong hash:", err)
	}

	fmt.Printf("Strong Hash: %s\n", strongHash)

	// Verify with custom params
	err = argon2id.CompareHashAndPassword(strongHash, password)
	if err != nil {
		log.Fatal("Strong password verification failed:", err)
	}
	fmt.Println("✓ Strong password verification successful!")

	// Example 3: Extract parameters from existing hash
	fmt.Println("3. Extracting parameters from hash:")
	params, err := argon2id.ExtractParams(strongHash)
	if err != nil {
		log.Fatal("Failed to extract parameters:", err)
	}

	fmt.Printf("Extracted parameters:\n")
	fmt.Printf("  Time: %d\n", params.Time)
	fmt.Printf("  Memory: %d KB\n", params.Memory)
	fmt.Printf("  Threads: %d\n", params.Threads)
	fmt.Printf("  Key Length: %d bytes\n", params.KeyLen)

	// Example 4: Wrong password demonstration
	fmt.Println("\n4. Wrong password demonstration:")
	wrongPassword := []byte("wrongPassword")
	err = argon2id.CompareHashAndPassword(hash, wrongPassword)
	if err != nil {
		fmt.Printf("✓ Correctly rejected wrong password: %v\n", err)
	} else {
		log.Fatal("ERROR: Wrong password was accepted!")
	}

	fmt.Println("\n=== Example completed successfully! ===")
}
