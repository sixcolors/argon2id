package argon2id

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenerateFromPassword(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	hash1, err := GenerateFromPassword([]byte("pa$$word"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if !hashRX.MatchString(string(hash1)) {
		t.Errorf("hash %q not in correct format", hash1)
	}

	hash2, err := GenerateFromPassword([]byte("pa$$word"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(string(hash1), string(hash2)) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	hash, err := GenerateFromPassword([]byte("pa$$word"), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = CompareHashAndPassword(hash, []byte("pa$$word"))
	if err != nil {
		t.Error("expected password and hash to match")
	}

	err = CompareHashAndPassword(hash, []byte("otherPa$$word"))
	if err == nil {
		t.Error("expected password and hash to not match")
	}
}

func TestCustomParams(t *testing.T) {
	params := &Params{
		Time:    4,
		Memory:  32 * 1024,
		Threads: 1,
		KeyLen:  32,
	}

	hash, err := GenerateFromPassword([]byte("test"), params)
	if err != nil {
		t.Fatal(err)
	}

	err = CompareHashAndPassword(hash, []byte("test"))
	if err != nil {
		t.Error("expected password and hash to match with custom params")
	}
}

func TestExtractParams(t *testing.T) {
	customParams := &Params{
		Time:    5,
		Memory:  32 * 1024,
		Threads: 4,
		KeyLen:  32,
	}

	hash, err := GenerateFromPassword([]byte("test"), customParams)
	if err != nil {
		t.Fatal(err)
	}

	extractedParams, err := ExtractParams(hash)
	if err != nil {
		t.Fatal(err)
	}

	if extractedParams.Time != 5 {
		t.Errorf("expected time 5, got %d", extractedParams.Time)
	}
	if extractedParams.Memory != 32*1024 {
		t.Errorf("expected memory 32768, got %d", extractedParams.Memory)
	}
	if extractedParams.Threads != 4 {
		t.Errorf("expected threads 4, got %d", extractedParams.Threads)
	}
}

func TestVariant(t *testing.T) {
	// Hash contains wrong variant
	err := CompareHashAndPassword([]byte("$argon2i$v=19$m=65536,t=1,p=2$mFe3kxhovyEByvwnUtr0ow$nU9AqnoPfzMOQhCHa9BDrQ+4bSfj69jgtvGu/2McCxU"), []byte("pa$$word"))
	if err != ErrIncompatibleVariant {
		t.Fatalf("expected error %s", ErrIncompatibleVariant)
	}
}

func TestVersion(t *testing.T) {
	// Hash contains wrong version
	err := CompareHashAndPassword([]byte("$argon2id$v=20$m=65536,t=4,p=1$K7EZEYAq/fjTQ6z2KREs3Q$aamcVSlySDBRfPrK0UkLNWQ6tRI6HPvyF5fyednj1HI"), []byte("pa$$word"))
	if err != ErrIncompatibleVersion {
		t.Fatalf("expected error %s", ErrIncompatibleVersion)
	}
}

func TestInvalidHash(t *testing.T) {
	// Hash is missing last part
	err := CompareHashAndPassword([]byte("$argon2id$v=20$m=65536,t=4,p=1$K7EZEYAq/fjTQ6z2KREs3Q"), []byte("pa$$word"))
	if err != ErrInvalidHash {
		t.Fatalf("expected error %s", ErrInvalidHash)
	}
}

// New comprehensive error tests
func TestDecodeHashErrors(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr error // Move error field last to optimize alignment
	}{
		{
			name:    "too few parts",
			hash:    "$argon2id$v=19$m=65536",
			wantErr: ErrInvalidHash,
		},
		// ...rest of test cases...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CompareHashAndPassword([]byte(tt.hash), []byte("password"))
			if err != tt.wantErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Also test ExtractParams
			_, err = ExtractParams([]byte(tt.hash))
			if err != tt.wantErr {
				t.Errorf("ExtractParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompareHashAndPasswordEdgeCases(t *testing.T) {
	hash, err := GenerateFromPassword([]byte("password123"), nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		password []byte
		wantErr  bool // Move bool field last to optimize alignment
	}{
		{"correct password", []byte("password123"), false},
		{"wrong password", []byte("wrongpassword"), true},
		{"empty password vs non-empty hash", []byte(""), true},
		{"similar password", []byte("password124"), true},
		{"case sensitive", []byte("Password123"), true},
		{"unicode password", []byte("päss🔑word"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CompareHashAndPassword(hash, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompareWithEmptyPassword(t *testing.T) {
	// Test hashing and comparing empty password
	hash, err := GenerateFromPassword([]byte(""), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = CompareHashAndPassword(hash, []byte(""))
	if err != nil {
		t.Error("empty password should match its own hash")
	}

	err = CompareHashAndPassword(hash, []byte("notempty"))
	if err == nil {
		t.Error("non-empty password should not match empty password hash")
	}
}

func TestCompareWithLongPassword(t *testing.T) {
	// Test with a very long password
	longPassword := make([]byte, 1000)
	for i := range longPassword {
		longPassword[i] = byte('a' + (i % 26))
	}

	hash, err := GenerateFromPassword(longPassword, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = CompareHashAndPassword(hash, longPassword)
	if err != nil {
		t.Error("long password should match its own hash")
	}

	// Modify one byte
	modifiedPassword := make([]byte, len(longPassword))
	copy(modifiedPassword, longPassword)
	modifiedPassword[500] = 'X'

	err = CompareHashAndPassword(hash, modifiedPassword)
	if err == nil {
		t.Error("modified long password should not match original hash")
	}
}

func TestDefaultParams(t *testing.T) {
	params := DefaultParams()

	if params.Time != DefaultTime {
		t.Errorf("expected time %d, got %d", DefaultTime, params.Time)
	}
	if params.Memory != DefaultMemory {
		t.Errorf("expected memory %d, got %d", DefaultMemory, params.Memory)
	}
	if params.Threads != DefaultThreads {
		t.Errorf("expected threads %d, got %d", DefaultThreads, params.Threads)
	}
	if params.KeyLen != DefaultKeyLen {
		t.Errorf("expected keylen %d, got %d", DefaultKeyLen, params.KeyLen)
	}
}

func TestParamBoundaryValues(t *testing.T) {
	tests := []struct {
		name   string
		params *Params
	}{
		{
			name: "minimum values",
			params: &Params{
				Time:    1,
				Memory:  1,
				Threads: 1,
				KeyLen:  1,
			},
		},
		{
			name: "large values",
			params: &Params{
				Time:    100,
				Memory:  1024 * 1024, // 1 GB
				Threads: 255,         // max uint8
				KeyLen:  128,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := GenerateFromPassword([]byte("test"), tt.params)
			if err != nil {
				t.Fatal(err)
			}

			err = CompareHashAndPassword(hash, []byte("test"))
			if err != nil {
				t.Errorf("password should match its hash with %s", tt.name)
			}

			// Verify params can be extracted
			extractedParams, err := ExtractParams(hash)
			if err != nil {
				t.Fatal(err)
			}

			if extractedParams.Time != tt.params.Time {
				t.Errorf("time mismatch: expected %d, got %d", tt.params.Time, extractedParams.Time)
			}
			if extractedParams.Memory != tt.params.Memory {
				t.Errorf("memory mismatch: expected %d, got %d", tt.params.Memory, extractedParams.Memory)
			}
			if extractedParams.Threads != tt.params.Threads {
				t.Errorf("threads mismatch: expected %d, got %d", tt.params.Threads, extractedParams.Threads)
			}
		})
	}
}
