# Examples

This directory contains example applications demonstrating how to use the argon2id package for secure password hashing.

These examples cover various use cases, from basic password hashing to web applications using popular Go frameworks. Each example is self-contained and can be run independently.

> **For installation, basic usage, migration from bcrypt, parameter customization, and security best practices, see the [main README](../README.md).**

## 🔒 Security Notice

**Important**: These examples are for educational purposes and demonstrate basic argon2id usage. For production applications, ensure you implement comprehensive security measures.

### 🛡️ Authentication & Authorization
- **Protection against timing attacks**: Use constant-time comparison functions
- **Rate limiting**: Implement authentication endpoint throttling to prevent brute force attacks
- **Secure session management**: Use cryptographically secure session tokens with proper expiration
- **Multi-factor authentication (MFA)**: Consider implementing 2FA/MFA for enhanced security

### 🔐 Data Protection
- **Proper input validation and sanitization**: Validate all user inputs against expected formats
- **Secure storage of sensitive data**: Use environment variables, key management services, or encrypted configuration
- **Database security**: Encrypt sensitive data at rest and use parameterized queries to prevent SQL injection
- **Secrets management**: Never hardcode API keys, passwords, or other secrets in source code

### 🌐 Web Security
- **HTTPS/TLS encryption**: Enforce TLS 1.2+ for all communications
- **Cross-Site Request Forgery (CSRF) protection**: Implement CSRF tokens for state-changing operations
- **Cross-Origin Resource Sharing (CORS) configuration**: Configure CORS policies appropriately for your use case
- **Use of secure cookies**: Set `Secure`, `HttpOnly`, and `SameSite` flags on authentication cookies
- **Content Security Policy (CSP)**: Implement CSP headers to prevent XSS attacks

### 📊 Monitoring & Maintenance
- **Comprehensive error handling and logging**: Log security events without exposing sensitive information
- **Regular security audits and updates**: Keep dependencies updated and conduct periodic security reviews
- **Intrusion detection**: Monitor for suspicious authentication patterns and failed login attempts
- **Security headers**: Implement security headers like `X-Frame-Options`, `X-Content-Type-Options`, etc.

### ⚠️ Production Checklist

Before deploying to production, verify:

- [ ] Strong password policies enforced
- [ ] Account lockout mechanisms in place
- [ ] Audit logging for authentication events
- [ ] Database connections using least privilege principles
- [ ] Error messages don't leak sensitive information
- [ ] Dependencies scanned for known vulnerabilities
- [ ] Backup and disaster recovery procedures tested
- [ ] Security incident response plan documented

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