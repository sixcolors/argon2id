# argon2id

[![Go Reference](https://pkg.go.dev/badge/github.com/sixcolors/argon2id.svg)](https://pkg.go.dev/github.com/sixcolors/argon2id)
[![Go Report Card](https://goreportcard.com/badge/github.com/sixcolors/argon2id)](https://goreportcard.com/report/github.com/sixcolors/argon2id)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go package providing Argon2ID password hashing with an API similar to `golang.org/x/crypto/bcrypt` for easy migration.

## Why this package?

This package provides a bcrypt-like API to make migration seamless while respecting Argon2ID's unique parameter structure (time, memory, threads) rather than bcrypt's single cost parameter.

## Installation

```bash
go get github.com/sixcolors/argon2id
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/sixcolors/argon2id"
)

func main() {
    password := []byte("mySecretPassword")
    
    // Generate hash with default parameters
    hash, err := argon2id.GenerateFromPassword(password, nil)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hash: %s\n", hash)
    
    // Compare password with hash
    err = argon2id.CompareHashAndPassword(hash, password)
    if err != nil {
        log.Fatal("Password doesn't match")
    }
    
    fmt.Println("Password matches!")
}
```

### Custom Parameters

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/sixcolors/argon2id"
)

func main() {
    password := []byte("mySecretPassword")
    
    // Custom parameters for higher security
    params := &argon2id.Params{
        Time:    4,          // Number of iterations
        Memory:  128 * 1024, // 128 MB memory usage
        Threads: 4,          // Number of threads
        KeyLen:  32,         // Length of generated key
    }
    
    hash, err := argon2id.GenerateFromPassword(password, params)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hash: %s\n", hash)
    
    // Comparison works with any valid hash regardless of parameters
    err = argon2id.CompareHashAndPassword(hash, password)
    if err != nil {
        log.Fatal("Password doesn't match")
    }
    
    fmt.Println("Password matches!")
}
```

### Extracting Parameters from Hash

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/sixcolors/argon2id"
)

func main() {
    password := []byte("mySecretPassword")
    hash, _ := argon2id.GenerateFromPassword(password, nil)
    
    // Extract parameters from existing hash
    params, err := argon2id.ExtractParams(hash)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Time: %d\n", params.Time)
    fmt.Printf("Memory: %d KB\n", params.Memory)
    fmt.Printf("Threads: %d\n", params.Threads)
    fmt.Printf("Key Length: %d\n", params.KeyLen)
}
```

### Migration from bcrypt

The API is designed to make migration from bcrypt straightforward:

```go
// Before (bcrypt)
hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
err = bcrypt.CompareHashAndPassword(hash, password)

// After (argon2id)
hash, err := argon2id.GenerateFromPassword(password, nil) // nil uses defaults
err = argon2id.CompareHashAndPassword(hash, password)
```

### Web Framework Integration (Fiber Example)

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/sixcolors/argon2id"
)

type User struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

func registerHandler(c *fiber.Ctx) error {
    var user User
    if err := c.BodyParser(&user); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }
    
    // Hash the password
    hashedPassword, err := argon2id.GenerateFromPassword([]byte(user.Password), nil)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
    }
    
    // Store user with hashed password
    // ... database logic here ...
    
    return c.JSON(fiber.Map{"message": "User registered successfully"})
}

func loginHandler(c *fiber.Ctx) error {
    var user User
    if err := c.BodyParser(&user); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }
    
    // Retrieve stored hash from database
    // storedHash := getHashFromDatabase(user.Email)
    
    // Compare password
    err := argon2id.CompareHashAndPassword(storedHash, []byte(user.Password))
    if err != nil {
        return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
    }
    
    return c.JSON(fiber.Map{"message": "Login successful"})
}
```

## Default Parameters

The package uses secure defaults suitable for most applications:

- **Time**: 3 iterations
- **Memory**: 64 MB
- **Threads**: 2
- **Key Length**: 32 bytes
- **Salt Length**: 16 bytes

These defaults provide a good balance between security and performance. For higher security requirements, increase the time and memory parameters.

## Hash Format

Hashes are encoded in the standard Argon2 format:

```
$argon2id$v=19$m=65536,t=3,p=2$saltBase64$hashBase64
```

Where:
- `argon2id` - Algorithm variant
- `v=19` - Argon2 version
- `m=65536` - Memory usage in KB
- `t=3` - Time cost (iterations)
- `p=2` - Parallelism (threads)
- `saltBase64` - Base64-encoded salt
- `hashBase64` - Base64-encoded hash

## Error Handling

The package provides specific error types for different failure modes:

- `ErrInvalidHash` - Hash format is invalid
- `ErrIncompatibleVersion` - Argon2 version mismatch
- `ErrIncompatibleVariant` - Wrong Argon2 variant (not argon2id)

## Performance Considerations

Argon2ID is intentionally slow to resist brute-force attacks. The default parameters are suitable for most web applications, but you may need to adjust them based on your hardware and security requirements:

- Increase `Time` for more security (slower)
- Increase `Memory` for more security (more RAM usage)
- Increase `Threads` to utilize more CPU cores
- Higher values = better security but slower performance

Test on your target hardware to find the right balance.

## Security

- Uses cryptographically secure random salt generation
- Implements constant-time comparison to prevent timing attacks
- Follows Argon2ID specification (RFC 9106)
- Salt is unique for each password hash

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by [@sixcolors](https://github.com/sixcolors)

## Acknowledgments

- The Go team for `golang.org/x/crypto/argon2`
- [alexedwards/argon2id](https://github.com/alexedwards/argon2id) for inspiration
- The Argon2 team for the excellent password hashing algorithm
