# Examples

This directory contains example applications demonstrating how to use the argon2id package for secure password hashing.

These examples cover various use cases, from basic password hashing to web applications using popular Go frameworks. Each example is self-contained and can be run independently.

## 🔒 Security Notice

**Important**: These examples are for educational purposes and demonstrate basic argon2id usage. For production applications, ensure you implement:

- Protection against timing attacks
- Rate limiting for authentication endpoints
- Proper input validation and sanitization
- Secure session management
- HTTPS/TLS encryption
- Comprehensive error handling and logging

## 📁 Available Examples

### Basic Example
**Location**: `basic/main.go`

Demonstrates fundamental argon2id operations:
- ✅ Generating hashes with default parameters
- ✅ Using custom parameters for enhanced security
- ✅ Extracting parameters from existing hashes
- ✅ Password verification and comparison

```bash
cd examples/basic
go run main.go
```

### Web Server Example
**Location**: `web-server/main.go`

Shows HTTP API implementation with:
- 🌐 Registration and login endpoints
- 📝 JSON request/response handling
- ⚠️ Proper error handling for web applications
- 💾 In-memory user storage (replace with database for production)

```bash
cd examples/web-server
go run main.go
```

**Test the endpoints**:

```bash
# Register a new user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Authenticate user
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'
```

### Fiber Framework Example
**Location**: `fiber-app/main.go`

Integration with the high-performance Fiber web framework:
- ⚡ Modern Go web framework usage
- 🔧 Middleware integration (CORS, logging, recovery)
- 🏗️ RESTful API design patterns
- 🚀 Optimized parameters for web applications
- 📊 Health check endpoint

```bash
cd examples/fiber-app
go mod tidy
go run main.go
```

**Explore the API**:

Visit http://localhost:3000 for API documentation, or test directly:

```bash
# Register a new user
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Authenticate user
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Check service health
curl http://localhost:3000/api/health
```

## 🔄 Migration from bcrypt

Migrating from bcrypt to argon2id is straightforward due to API similarity:

```go
// Before (bcrypt)
hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
if err != nil {
    return err
}
err = bcrypt.CompareHashAndPassword(hash, password)

// After (argon2id)
hash, err := argon2id.GenerateFromPassword(password, nil)
if err != nil {
    return err
}
err = argon2id.CompareHashAndPassword(hash, password)
```

### Key Advantages of argon2id

- **Memory-hard**: Resistant to GPU/ASIC attacks
- **Tunable parameters**: Fine-grained control over time, memory, and parallelism
- **Modern standard**: Winner of the Password Hashing Competition
- **Better security**: More resistant to various attack vectors than bcrypt

### Parameter Customization

Unlike bcrypt's single cost parameter, argon2id offers granular control:

```go
params := &argon2id.Params{
    Memory:      64 * 1024, // 64 MB
    Iterations:  3,         // 3 iterations
    Parallelism: 2,         // 2 threads
    SaltLength:  16,        // 16-byte salt
    KeyLength:   32,        // 32-byte key
}

hash, err := argon2id.GenerateFromPassword(password, params)
```

## 🏃‍♂️ Quick Start

1. **Clone and navigate**:
   ```bash
   git clone <repository-url>
   cd argon2id/examples
   ```

2. **Choose an example**:
   ```bash
   cd basic  # or web-server, or fiber-app
   ```

3. **Install dependencies** (if needed):
   ```bash
   go mod tidy
   ```

4. **Run the example**:
   ```bash
   go run main.go
   ```

## 📚 Additional Resources

- [argon2id Package Documentation](../README.md)
- [Argon2 Specification](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-13)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)