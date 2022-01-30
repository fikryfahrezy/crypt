## Benchmark

```
goos: windows
goarch: amd64
pkg: github.com/fikryfahrezy/crypt/agron2
cpu: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz
BenchmarkArgon2i
BenchmarkArgon2i/_Time:_3_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_3_Memory:_32_MB,_Threads:_1-8                 13          86954546 ns/op        33559206 B/op         38 allocs/op
BenchmarkArgon2i/_Time:_4_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_4_Memory:_32_MB,_Threads:_1-8                 10         102367670 ns/op        33559497 B/op         46 allocs/op
BenchmarkArgon2i/_Time:_5_Memory:_32_MB,_Threads:_1
BenchmarkArgon2i/_Time:_5_Memory:_32_MB,_Threads:_1-8                  9         124587944 ns/op        33559749 B/op         54 allocs/op
BenchmarkArgon2i/_Time:_3_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_3_Memory:_64_MB,_Threads:_4-8                 20          56297650 ns/op        67118368 B/op         87 allocs/op
BenchmarkArgon2i/_Time:_4_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_4_Memory:_64_MB,_Threads:_4-8                 14          72889379 ns/op        67118923 B/op        106 allocs/op
BenchmarkArgon2i/_Time:_5_Memory:_64_MB,_Threads:_4
BenchmarkArgon2i/_Time:_5_Memory:_64_MB,_Threads:_4-8                 12          93967467 ns/op        67121706 B/op        130 allocs/op
BenchmarkArgon2id
BenchmarkArgon2id/_Time:_3,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_3,_Memory:_32_MB,_Threads:_1-8               15          77463813 ns/op        33559203 B/op         38 allocs/op
BenchmarkArgon2id/_Time:_4,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_4,_Memory:_32_MB,_Threads:_1-8               12          98362167 ns/op        33559488 B/op         46 allocs/op
BenchmarkArgon2id/_Time:_5,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2id/_Time:_5,_Memory:_32_MB,_Threads:_1-8                9         121064878 ns/op        33559708 B/op         54 allocs/op
BenchmarkArgon2id/_Time:_3,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_3,_Memory:_64_MB,_Threads:_4-8               18          61998589 ns/op        67118048 B/op         86 allocs/op
BenchmarkArgon2id/_Time:_4,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_4,_Memory:_64_MB,_Threads:_4-8               13          79789146 ns/op        67118864 B/op        106 allocs/op
BenchmarkArgon2id/_Time:_5,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2id/_Time:_5,_Memory:_64_MB,_Threads:_4-8               10         100198260 ns/op        67119715 B/op        126 allocs/op
BenchmarkArgon2iVerify
BenchmarkArgon2iVerify/_Time:_3_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_3_Memory:_32_MB,_Threads:_1-8           15          76199833 ns/op        33559197 B/op         38 allocs/op
BenchmarkArgon2iVerify/_Time:_4_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_4_Memory:_32_MB,_Threads:_1-8           12         105051167 ns/op        33559456 B/op         46 allocs/op
BenchmarkArgon2iVerify/_Time:_5_Memory:_32_MB,_Threads:_1
BenchmarkArgon2iVerify/_Time:_5_Memory:_32_MB,_Threads:_1-8            8         126835500 ns/op        33559734 B/op         54 allocs/op
BenchmarkArgon2iVerify/_Time:_3_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_3_Memory:_64_MB,_Threads:_4-8           21          63374238 ns/op        67118045 B/op         86 allocs/op
BenchmarkArgon2iVerify/_Time:_4_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_4_Memory:_64_MB,_Threads:_4-8           14          84531129 ns/op        67119229 B/op        106 allocs/op
BenchmarkArgon2iVerify/_Time:_5_Memory:_64_MB,_Threads:_4
BenchmarkArgon2iVerify/_Time:_5_Memory:_64_MB,_Threads:_4-8           10         122370230 ns/op        67119696 B/op        126 allocs/op
BenchmarkArgon2idVerify
BenchmarkArgon2idVerify/_Time:_3,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_3,_Memory:_32_MB,_Threads:_1-8         14          75075014 ns/op        33559199 B/op         38 allocs/op
BenchmarkArgon2idVerify/_Time:_4,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_4,_Memory:_32_MB,_Threads:_1-8         12         100775450 ns/op        33559481 B/op         46 allocs/op
BenchmarkArgon2idVerify/_Time:_5,_Memory:_32_MB,_Threads:_1
BenchmarkArgon2idVerify/_Time:_5,_Memory:_32_MB,_Threads:_1-8          9         126402156 ns/op        33559751 B/op         54 allocs/op
BenchmarkArgon2idVerify/_Time:_3,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_3,_Memory:_64_MB,_Threads:_4-8         19          56631321 ns/op        67118057 B/op         86 allocs/op
BenchmarkArgon2idVerify/_Time:_4,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_4,_Memory:_64_MB,_Threads:_4-8         14          84689293 ns/op        67118877 B/op        106 allocs/op
BenchmarkArgon2idVerify/_Time:_5,_Memory:_64_MB,_Threads:_4
BenchmarkArgon2idVerify/_Time:_5,_Memory:_64_MB,_Threads:_4-8         10         102999150 ns/op        67119715 B/op        126 allocs/op
```

## References

- [P-H-C / phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
- [How to Hash and Verify Passwords With Argon2 in Go](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go)
- [Argon2 Password Hashing](https://golangcode.com/argon2-password-hashing/)