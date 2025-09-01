module migration

go 1.25.0

require (
	github.com/sixcolors/argon2id v1.0.0
	golang.org/x/crypto v0.41.0
)

require golang.org/x/sys v0.35.0 // indirect

replace github.com/sixcolors/argon2id => ../..
