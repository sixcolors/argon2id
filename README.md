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

## Basic Usage

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

## Security Notice

**Important:** For production use, implement comprehensive security measures:

- Protection against timing attacks (use constant-time comparison)
- Rate limiting for authentication endpoints
- Proper input validation and sanitization
- Secure session management (cryptographically secure tokens, secure cookies)
- Cross-Site Request Forgery (CSRF) protection
- Cross-Origin Resource Sharing (CORS) configuration
- Secure storage of sensitive data (e.g., environment variables)
- Regular security audits and updates
- HTTPS/TLS encryption
- Comprehensive error handling and logging

See [examples/README.md](examples/README.md#-security-notice) for a detailed checklist.

## Examples

Explore the [`examples/`](examples) directory for real-world usage:

- **[Migration Example](examples/migration/main.go):** Automatic migration from bcrypt to argon2id during login
- **[Basic Example](examples/basic/main.go):** Hashing, verifying, and extracting parameters.
- **[Web Server Example](examples/webserver/main.go):** Simple HTTP API for registration and login.
- **[Fiber Framework Example](examples/fiber-app/main.go):** Integration with the Fiber web framework.

See [examples/README.md](examples/README.md) for details and usage instructions.

## Migration from bcrypt

Switching from bcrypt is straightforward:

```go
// Before (bcrypt)
hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
err = bcrypt.CompareHashAndPassword(hash, password)

// After (argon2id)
hash, err := argon2id.GenerateFromPassword(password, nil) // nil uses defaults
err = argon2id.CompareHashAndPassword(hash, password)
```

The API is intentionally similar to make migration as seamless as possible.

## Advanced Features

### Parameter Extraction

Extract parameters from existing hashes for analysis or migration:

```go
params, err := argon2id.ExtractParams(hash)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Hash uses %d iterations, %d KB memory\n", params.Time, params.Memory)
```

### Rehash Detection

Check if a hash needs rehashing with stronger parameters:

```go
newParams := &argon2id.Params{
    Time:    6,          // Stronger than default
    Memory:  128 * 1024, // More memory
    Threads: 4,
    KeyLen:  32,
}

needsRehash, err := argon2id.NeedsRehash(hash, newParams)
if err != nil {
    log.Fatal(err)
}

if needsRehash {
    // Rehash with stronger parameters
    newHash, err := argon2id.GenerateFromPassword(password, newParams)
    // Update stored hash...
}
```

## Documentation

- [API Reference](https://pkg.go.dev/github.com/sixcolors/argon2id)
- [Examples and advanced usage](examples/README.md)

## Default Parameters

The package uses secure defaults suitable for most applications:

- **Time**: 3 iterations
- **Memory**: 64 MB
- **Threads**: 2
- **Key Length**: 32 bytes
- **Salt Length**: 16 bytes

These defaults provide a good balance between security and performance. For higher security requirements, increase the time and memory parameters.

## Parameter Validation

The package enforces parameter limits to ensure security and prevent abuse:

### Minimum Values (Security)
- **Time**: ≥ 1 iteration
- **Memory**: ≥ 8 KB
- **Threads**: ≥ 1 thread
- **KeyLen**: ≥ 4 bytes

### Maximum Values (DoS Protection)
- **Time**: ≤ 100 iterations
- **Memory**: ≤ 1 GB (1,048,576 KB)
- **KeyLen**: ≤ 128 bytes

These limits prevent:
- **Weak configurations** that could compromise security
- **Resource exhaustion** attacks via excessive memory/time usage
- **Unreasonably large outputs** that waste storage/computation

If you need parameters outside these ranges, the limits are intentionally conservative but can be adjusted by modifying the validation in `GenerateFromPassword()`.

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

- `ErrInvalidHash` - Hash format is invalid or malformed
- `ErrHashTooShort` - Hash string is too short to be valid
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
