// https://cs.opensource.google/go/x/crypto/+/198e4374:argon2/argon2_test.go

package agron2_test

import (
	"encoding/hex"
	"fmt"
	"github.com/fikryfahrezy/crypt/agron2"
	"testing"

	"golang.org/x/crypto/argon2"
)

var testVectors = []struct {
	mode         agron2.Argon2Type
	time, memory uint32
	threads      uint8
	hash         string
}{
	{
		mode: agron2.Argon2I, time: 1, memory: 64, threads: 1,
		hash: "b9c401d1844a67d50eae3967dc28870b22e508092e861a37",
	},
	{
		mode: agron2.Argon2Id, time: 1, memory: 64, threads: 1,
		hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
	},
	{
		mode: agron2.Argon2I, time: 2, memory: 64, threads: 1,
		hash: "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64",
	},
	{
		mode: agron2.Argon2Id, time: 2, memory: 64, threads: 1,
		hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
	},
	{
		mode: agron2.Argon2I, time: 2, memory: 64, threads: 2,
		hash: "2089f3e78a799720f80af806553128f29b132cafe40d059f",
	},
	{
		mode: agron2.Argon2Id, time: 2, memory: 64, threads: 2,
		hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
	},
	{
		mode: agron2.Argon2I, time: 3, memory: 256, threads: 2,
		hash: "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6",
	},
	{
		mode: agron2.Argon2Id, time: 3, memory: 256, threads: 2,
		hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
	},
	{
		mode: agron2.Argon2I, time: 4, memory: 4096, threads: 4,
		hash: "a11f7b7f3f93f02ad4bddb59ab62d121e278369288a0d0e7",
	},
	{
		mode: agron2.Argon2Id, time: 4, memory: 4096, threads: 4,
		hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a",
	},
	{
		mode: agron2.Argon2I, time: 4, memory: 1024, threads: 8,
		hash: "0cdd3956aa35e6b475a7b0c63488822f774f15b43f6e6e17",
	},
	{
		mode: agron2.Argon2Id, time: 4, memory: 1024, threads: 8,
		hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f",
	},
	{
		mode: agron2.Argon2I, time: 2, memory: 64, threads: 3,
		hash: "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6",
	},
	{
		mode: agron2.Argon2Id, time: 2, memory: 64, threads: 3,
		hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079",
	},
	{
		mode: agron2.Argon2I, time: 3, memory: 1024, threads: 6,
		hash: "d236b29c2b2a09babee842b0dec6aa1e83ccbdea8023dced",
	},
	{
		mode: agron2.Argon2Id, time: 3, memory: 1024, threads: 6,
		hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016",
	},
}

func TestVectors(t *testing.T) {
	password, salt := "password", "somesalt"
	for i, v := range testVectors {
		want, err := hex.DecodeString(v.hash)
		if err != nil {
			t.Fatalf("Test %d: failed to decode hash: %v", i, err)
		}

		ctx := agron2.Argon2Context{
			Version:   argon2.Version,
			Tcost:     v.time,
			Mcost:     v.memory,
			Threads:   v.threads,
			Secretlen: uint32(len(want)),
			Pwd:       password,
			Salt:      salt,
		}
		hash, err := agron2.Argon2Ctx(ctx, v.mode)
		if err != nil {
			t.Fatalf("Test %d: failed to get argon context: %v", i, err)
		}

		err = agron2.Argon2VerifyCtx(ctx, hash, v.mode)
		if err != nil {
			t.Errorf("Test %d - error: %v", i, err)
		}
	}
}

func benchmarkArgon2(mode agron2.Argon2Type, time, memory uint32, threads uint8, keyLen uint32, b *testing.B) {
	password := "password"
	salt := "choosing random salts is hard"
	ctx := agron2.Argon2Context{
		Version:   argon2.Version,
		Tcost:     time,
		Mcost:     memory,
		Threads:   threads,
		Secretlen: keyLen,
		Pwd:       password,
		Salt:      salt,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		agron2.Argon2Ctx(ctx, mode)
	}
}

func BenchmarkArgon2i(b *testing.B) {
	b.Run(" Time: 3 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2I, 5, 64*1024, 4, 32, b) })
}

func BenchmarkArgon2id(b *testing.B) {
	b.Run(" Time: 3, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(agron2.Argon2Id, 5, 64*1024, 4, 32, b) })
}

func benchmarkArgon2Verify(mode agron2.Argon2Type, time, memory uint32, threads uint8, keyLen uint32, b *testing.B) {
	password := "password"
	salt := "choosing random salts is hard"
	ctx := agron2.Argon2Context{
		Version:   argon2.Version,
		Tcost:     time,
		Mcost:     memory,
		Threads:   threads,
		Secretlen: keyLen,
		Pwd:       password,
		Salt:      salt,
	}
	hash, err := agron2.Argon2Ctx(ctx, mode)
	if err != nil {
		panic(fmt.Sprintf("Test failed to get argon context: %v", err))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		agron2.Argon2VerifyCtx(ctx, hash, mode)
	}
}

func BenchmarkArgon2iVerify(b *testing.B) {
	b.Run(" Time: 3 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5 Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5 Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2I, 5, 64*1024, 4, 32, b) })
}

func BenchmarkArgon2idVerify(b *testing.B) {
	b.Run(" Time: 3, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 3, 32*1024, 1, 32, b) })
	b.Run(" Time: 4, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 4, 32*1024, 1, 32, b) })
	b.Run(" Time: 5, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 5, 32*1024, 1, 32, b) })
	b.Run(" Time: 3, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 3, 64*1024, 4, 32, b) })
	b.Run(" Time: 4, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 4, 64*1024, 4, 32, b) })
	b.Run(" Time: 5, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2Verify(agron2.Argon2Id, 5, 64*1024, 4, 32, b) })
}
