package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/sixcolors/argon2id"
)

// User represents a user in our system
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"` // Never send password in response
}

// UserRequest for registration and login
type UserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// In-memory user storage (use database in production)
var users = make(map[string]string) // email -> hashed password
var userID = 1

// Custom Argon2ID parameters optimized for web applications
var webParams = &argon2id.Params{
	Time:    2,         // Fast iterations for web
	Memory:  64 * 1024, // 64 MB
	Threads: 2,         // 2 threads
	KeyLen:  32,        // 32-byte hash
}

func main() {
	app := fiber.New(fiber.Config{
		AppName:               "Argon2ID Fiber Example",
		DisableStartupMessage: true, // Suppress Fiber's startup banner
	})

	// Middleware
	app.Use(logger.New())
	app.Use(cors.New())

	// Routes
	app.Post("/api/register", registerUser)
	app.Post("/api/login", loginUser)
	app.Get("/api/health", healthCheck)

	// Welcome route with usage info
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Argon2ID + Fiber Example API",
			"endpoints": fiber.Map{
				"POST /api/register": "Register a new user",
				"POST /api/login":    "Login user",
				"GET /api/health":    "Health check",
			},
			"argon2id_params": fiber.Map{
				"time":    webParams.Time,
				"memory":  webParams.Memory,
				"threads": webParams.Threads,
				"keylen":  webParams.KeyLen,
			},
		})
	})

	// Custom startup message
	fmt.Println("=== Argon2ID Fiber Example ===")
	fmt.Printf("Using Argon2ID parameters:\n")
	fmt.Printf("  Time: %d\n", webParams.Time)
	fmt.Printf("  Memory: %d KB\n", webParams.Memory)
	fmt.Printf("  Threads: %d\n", webParams.Threads)
	fmt.Printf("  Key Length: %d bytes\n", webParams.KeyLen)
	fmt.Println()

	fmt.Println("🚀 Server starting on :3000")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /             - API information")
	fmt.Println("  POST /api/register - Register a new user")
	fmt.Println("  POST /api/login    - Login with credentials")
	fmt.Println("  GET  /api/health   - Health check")
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Println(`  curl -X POST http://localhost:3000/api/register \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"mypassword123"}'`)
	fmt.Println()
	fmt.Println(`  curl -X POST http://localhost:3000/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"mypassword123"}'`)
	fmt.Println()
	fmt.Println(`  curl http://localhost:3000/api/health`)

	log.Fatal(app.Listen(":3000"))
}

func registerUser(c *fiber.Ctx) error {
	var req UserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Basic validation
	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Check if user already exists
	if _, exists := users[req.Email]; exists {
		return c.Status(409).JSON(fiber.Map{
			"error": "User already exists",
		})
	}

	// Hash password with Argon2ID
	hashedPassword, err := argon2id.GenerateFromPassword([]byte(req.Password), webParams)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create user",
		})
	}

	// Store user
	users[req.Email] = string(hashedPassword)

	log.Printf("✅ User registered: %s", req.Email)
	return c.Status(201).JSON(fiber.Map{
		"message": "User registered successfully",
		"user": fiber.Map{
			"id":    userID,
			"email": req.Email,
		},
	})
}

func loginUser(c *fiber.Ctx) error {
	var req UserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Basic validation
	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Get stored hash
	storedHash, exists := users[req.Email]
	if !exists {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Compare password with hash using Argon2ID
	err := argon2id.CompareHashAndPassword([]byte(storedHash), []byte(req.Password))
	if err != nil {
		log.Printf("❌ Login failed for %s", req.Email)
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	log.Printf("✅ User logged in: %s", req.Email)
	return c.JSON(fiber.Map{
		"message": "Login successful",
		"user": fiber.Map{
			"email": req.Email,
		},
	})
}

func healthCheck(c *fiber.Ctx) error {
	// Extract params from a test hash to verify library is working
	testHash, _ := argon2id.GenerateFromPassword([]byte("test"), webParams)
	params, _ := argon2id.ExtractParams(testHash)

	return c.JSON(fiber.Map{
		"status": "healthy",
		"argon2id": fiber.Map{
			"working": true,
			"params": fiber.Map{
				"time":    params.Time,
				"memory":  params.Memory,
				"threads": params.Threads,
				"keylen":  params.KeyLen,
			},
		},
	})
}
