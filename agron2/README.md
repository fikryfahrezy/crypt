## Benchmark

```
goos: windows
goarch: amd64
pkg: github.com/fikryfahrezy/crypt/agron2
cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
BenchmarkArgon2i
BenchmarkArgon2i/_Time:_3_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_3_Memory:_32_MB,_Threads:_1-8                 15          73196167 ns/op        33559235 B/op         38 allocs/op
BenchmarkArgon2i/_Time:_4_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_4_Memory:_32_MB,_Threads:_1-8                 12          95384108 ns/op        33559512 B/op         46 allocs/op
BenchmarkArgon2i/_Time:_5_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_5_Memory:_32_MB,_Threads:_1-8                  9         122983000 ns/op        33559760 B/op         54 allocs/op
BenchmarkArgon2i/_Time:_3_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_3_Memory:_64_MB,_Threads:_4-8                 19          62837926 ns/op        67118357 B/op         87 allocs/op
BenchmarkArgon2i/_Time:_4_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_4_Memory:_64_MB,_Threads:_4-8                 15          80833153 ns/op        67118932 B/op        106 allocs/op
BenchmarkArgon2i/_Time:_5_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_5_Memory:_64_MB,_Threads:_4-8                 13          85465838 ns/op        67119718 B/op        126 allocs/op
BenchmarkArgon2id
BenchmarkArgon2id/_Time:_3,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_3,_Memory:_32_MB,_Threads:_1-8               14          72565071 ns/op        33559222 B/op         38 allocs/op
BenchmarkArgon2id/_Time:_4,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_4,_Memory:_32_MB,_Threads:_1-8               12          96643808 ns/op        33559467 B/op         46 allocs/op
BenchmarkArgon2id/_Time:_5,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_5,_Memory:_32_MB,_Threads:_1-8                9         118472811 ns/op        33559719 B/op         54 allocs/op
BenchmarkArgon2id/_Time:_3,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_3,_Memory:_64_MB,_Threads:_4-8               19          57980211 ns/op        67118047 B/op         86 allocs/op
BenchmarkArgon2id/_Time:_4,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_4,_Memory:_64_MB,_Threads:_4-8               14          75400779 ns/op        67118891 B/op        106 allocs/op
BenchmarkArgon2id/_Time:_5,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_5,_Memory:_64_MB,_Threads:_4-8               12          91809117 ns/op        67120085 B/op        127 allocs/op
BenchmarkArgon2iVerifyCtx
BenchmarkArgon2iVerifyCtx/_Time:_3_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerifyCtx/_Time:_3_Memory:_32_MB,_Threads:_1-8                14          72646493 ns/op        33559228 B/op         38 allocs/op
BenchmarkArgon2iVerifyCtx/_Time:_4_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerifyCtx/_Time:_4_Memory:_32_MB,_Threads:_1-8                12          95754358 ns/op        33559534 B/op         46 allocs/op
BenchmarkArgon2iVerifyCtx/_Time:_5_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerifyCtx/_Time:_5_Memory:_32_MB,_Threads:_1-8                 9         119752689 ns/op        33559739 B/op         54 allocs/op
BenchmarkArgon2iVerifyCtx/_Time:_3_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerifyCtx/_Time:_3_Memory:_64_MB,_Threads:_4-8                19          53102500 ns/op        67118203 B/op         86 allocs/op
BenchmarkArgon2iVerifyCtx/_Time:_4_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerifyCtx/_Time:_4_Memory:_64_MB,_Threads:_4-8                16         110879269 ns/op        67118888 B/op        106 allocs/op
BenchmarkArgon2iVerifyCtx/_Time:_5_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerifyCtx/_Time:_5_Memory:_64_MB,_Threads:_4-8                10         102357980 ns/op        67119715 B/op        126 allocs/op
BenchmarkArgon2idVerifyCtx
BenchmarkArgon2idVerifyCtx/_Time:_3,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerifyCtx/_Time:_3,_Memory:_32_MB,_Threads:_1-8              14          73766064 ns/op        33559208 B/op         38 allocs/op
BenchmarkArgon2idVerifyCtx/_Time:_4,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerifyCtx/_Time:_4,_Memory:_32_MB,_Threads:_1-8              12          98880017 ns/op        33559465 B/op         46 allocs/op
BenchmarkArgon2idVerifyCtx/_Time:_5,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerifyCtx/_Time:_5,_Memory:_32_MB,_Threads:_1-8               8         126674112 ns/op        33559723 B/op         54 allocs/op
BenchmarkArgon2idVerifyCtx/_Time:_3,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerifyCtx/_Time:_3,_Memory:_64_MB,_Threads:_4-8              18          66720456 ns/op        67118058 B/op         86 allocs/op
BenchmarkArgon2idVerifyCtx/_Time:_4,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerifyCtx/_Time:_4,_Memory:_64_MB,_Threads:_4-8              13         133187138 ns/op        67119092 B/op        106 allocs/op
BenchmarkArgon2idVerifyCtx/_Time:_5,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerifyCtx/_Time:_5,_Memory:_64_MB,_Threads:_4-8               9         111430911 ns/op        67119728 B/op        126 allocs/op
BenchmarkArgon2iVerify
BenchmarkArgon2iVerify/_Time:_3_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_3_Memory:_32_MB,_Threads:_1-8                   14          74702486 ns/op        33560774 B/op         54 allocs/op
BenchmarkArgon2iVerify/_Time:_4_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_4_Memory:_32_MB,_Threads:_1-8                   12          99218950 ns/op        33561074 B/op         62 allocs/op
BenchmarkArgon2iVerify/_Time:_5_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_5_Memory:_32_MB,_Threads:_1-8                    9         128535400 ns/op        33561342 B/op         71 allocs/op
BenchmarkArgon2iVerify/_Time:_3_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_3_Memory:_64_MB,_Threads:_4-8                   19          56882653 ns/op        67119674 B/op        102 allocs/op
BenchmarkArgon2iVerify/_Time:_4_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_4_Memory:_64_MB,_Threads:_4-8                   16          81522544 ns/op        67120494 B/op        122 allocs/op
BenchmarkArgon2iVerify/_Time:_5_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_5_Memory:_64_MB,_Threads:_4-8                   10         101968200 ns/op        67121344 B/op        143 allocs/op
BenchmarkArgon2idVerify
BenchmarkArgon2idVerify/_Time:_3,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_3,_Memory:_32_MB,_Threads:_1-8                 14          75662893 ns/op        33560750 B/op         53 allocs/op
BenchmarkArgon2idVerify/_Time:_4,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_4,_Memory:_32_MB,_Threads:_1-8                 10         105690670 ns/op        33561025 B/op         62 allocs/op
BenchmarkArgon2idVerify/_Time:_5,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_5,_Memory:_32_MB,_Threads:_1-8                  9         123324889 ns/op        33561307 B/op         70 allocs/op
BenchmarkArgon2idVerify/_Time:_3,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_3,_Memory:_64_MB,_Threads:_4-8                 19          57352205 ns/op        67119680 B/op        103 allocs/op
BenchmarkArgon2idVerify/_Time:_4,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_4,_Memory:_64_MB,_Threads:_4-8                 16          81516356 ns/op        67120480 B/op        122 allocs/op
BenchmarkArgon2idVerify/_Time:_5,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_5,_Memory:_64_MB,_Threads:_4-8                 10         101050640 ns/op        67121324 B/op        142 allocs/op
```

## References

- [P-H-C / phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
- [How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)
- [Argon2 Password Hashing](https://golangcode.com/argon2-password-hashing/)