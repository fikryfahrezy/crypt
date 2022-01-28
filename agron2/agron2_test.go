package agron2

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestOne(t *testing.T) {
	pw := "password"
	salt := "saltsalt"
	ctx := Argon2Context{
		Pwd:       []byte(pw),
		Pwdlen:    uint32(len(pw)),
		Salt:      []byte(salt),
		Saltlen:   uint32(len(salt)),
		Secretlen: 32,
		Mcost:     32 * 1024,
		Threads:   4,
		Tcost:     3,
	}
	key, err := Argon2Ctx(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(ctx.Salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(key)
	format := "$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, ctx.Mcost, ctx.Tcost, ctx.Threads, b64Salt, b64Hash)

	err = Argon2Verify([]byte(full), []byte(pw), 1)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkOne(b *testing.B) {
	pw := "password"
	salt := "saltsalt"
	ctx := Argon2Context{
		Pwd:       []byte(pw),
		Pwdlen:    uint32(len(pw)),
		Salt:      []byte(salt),
		Saltlen:   uint32(len(salt)),
		Secretlen: 32,
		Mcost:     32 * 1024,
		Threads:   4,
		Tcost:     3,
	}
	key, err := Argon2Ctx(ctx, 1)
	if err != nil {
		b.Fatal(err)
	}

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(ctx.Salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(key)
	format := "$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, ctx.Mcost, ctx.Tcost, ctx.Threads, b64Salt, b64Hash)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Argon2Verify([]byte(full), []byte(pw), 1)
	}
}
