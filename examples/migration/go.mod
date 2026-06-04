module migration

go 1.26.0

require (
	github.com/sixcolors/argon2id v1.2.0
	golang.org/x/crypto v0.52.0
)

require golang.org/x/sys v0.45.0 // indirect

replace github.com/sixcolors/argon2id => ../..
