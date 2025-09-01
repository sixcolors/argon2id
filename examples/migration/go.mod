module migration

go 1.24.3

require (
	github.com/sixcolors/argon2id v0.0.0
	golang.org/x/crypto v0.39.0
)

require golang.org/x/sys v0.33.0 // indirect

replace github.com/sixcolors/argon2id => ../..
