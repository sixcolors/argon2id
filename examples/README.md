# Examples

This directory contains example applications demonstrating how to use the argon2id package.

## Basic Example

The basic example (`basic/main.go`) shows fundamental usage:
- Generating hashes with default parameters
- Using custom parameters for higher security  
- Extracting parameters from existing hashes
- Password verification

```bash
cd examples/basic
go run main.go
```

## Web Server Example

The web server example (`web-server/main.go`) demonstrates:
- HTTP API with registration and login endpoints
- Proper error handling for web applications
- JSON request/response handling
- In-memory user storage (use a database in production)

```bash
cd examples/web-server
go run main.go
```

Test the endpoints:

```bash
# Register a user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Login
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'
```

## Fiber Framework Example

The Fiber example (`fiber-app/main.go`) shows integration with the popular Fiber web framework:
- Modern Go web framework usage
- Middleware integration (CORS, logging)
- RESTful API design
- Optimized parameters for web applications

```bash
cd examples/fiber-app
go mod tidy
go run main.go
```

Visit http://localhost:3000 for API information, or test the endpoints:

```bash
# Register
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Login  
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword123"}'

# Health check
curl http://localhost:3000/api/health
```

## Migration from bcrypt

All examples demonstrate the API similarity to bcrypt, showing how easy it is to migrate:

```go
// Before (bcrypt)
hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
err = bcrypt.CompareHashAndPassword(hash, password)

// After (argon2id)  
hash, err := argon2id.GenerateFromPassword(password, nil)
err = argon2id.CompareHashAndPassword(hash, password)
```

The main difference is that argon2id allows more granular parameter control through the `Params` struct.