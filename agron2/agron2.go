package agron2

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Context struct {
	Pwd       string // password string
	Salt      string // salt string
	Secretlen uint32 // key length
	Mcost     uint32 // amount of memory requested (KB)
	Threads   uint8  // maximum number of threads or lanes
	Tcost     uint32 // number of passes
	Version   int    // version number
}

type Argon2Type int

const (
	Argon2D Argon2Type = iota
	Argon2I
	Argon2Id
)

const Uint32Max = 4294967295

func Argon2Min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

const (
	Argon2MinPwdLength  uint32 = 0 // Minimum and maximum password length in bytes
	Argon2MaxPwdLength  uint32 = 0xFFFFFFFF
	Argon2MinSaltLength uint32 = 8 // Minimum and maximum salt length in bytes
	Argon2MaxSaltLength uint32 = 0xFFFFFFFF
	Argon2MinSecret     uint32 = 0 // Minimum and maximum key length in bytes
	Argon2MaxSecret     uint32 = 0xFFFFFFFF
	Argon2SyncPoints    uint32 = 4
	Argon2MinMemory     uint32 = 2 * Argon2SyncPoints // 2 blocks per slice
	Argon2MinThreads    uint32 = 1
	Argon2MaxThreads    uint32 = 0xFFFFFF
	Argon2MinTime       uint32 = 1
	Argon2MaxTime       uint32 = 0xFFFFFFFF
)

var (
	CharBit             uint64 = 8                                           // It should be 7 in older machine
	Argon2MaxMemoryBits uint64 = Argon2Min(32, strconv.IntSize*CharBit-10-1) // Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB)
	Argon2MaxMemory     uint64 = Argon2Min(uint64(0xFFFFFFFF), uint64(1)<<Argon2MaxMemoryBits)
)

const (
	Argon2Ok = iota
	Argon2PwdTooShort
	Argon2PwdTooLong
	Argon2SaltTooShort
	Argon2SaltTooLong
	Argon2SecretTooShort
	Argon2SecretTooLong
	Argon2TimeTooSmall
	Argon2TimeTooLarge
	Argon2MemoryTooLittle
	Argon2MemoryTooMuch
	Argon2PwdPtrMismatch
	Argon2SaltPtrMismatch
	Argon2SecretPtrMismatch
	Argon2IncorrectType
	Argon2ThreadsTooFew
	Argon2ThreadsTooMany
	Argon2DecodingFail
	Argon2VerifyMismatch
)

func Argon2ErrorMessage(errorCode int) string {
	switch errorCode {
	case Argon2Ok:
		return "OK"
	case Argon2PwdTooShort:
		return "Password is too short"
	case Argon2PwdTooLong:
		return "Password is too long"
	case Argon2SaltTooShort:
		return "Salt is too short"
	case Argon2SaltTooLong:
		return "Salt is too long"
	case Argon2SecretTooShort:
		return "Secret is too short"
	case Argon2SecretTooLong:
		return "Secret is too long"
	case Argon2TimeTooSmall:
		return "Time cost is too small"
	case Argon2TimeTooLarge:
		return "Time cost is too large"
	case Argon2MemoryTooLittle:
		return "Memory cost is too small"
	case Argon2MemoryTooMuch:
		return "Memory cost is too large"
	case Argon2PwdPtrMismatch:
		return "Password pointer is NULL, but password length is not 0"
	case Argon2SaltPtrMismatch:
		return "Salt pointer is NULL, but salt length is not 0"
	case Argon2SecretPtrMismatch:
		return "Secret pointer is NULL, but secret length is not 0"
	case Argon2IncorrectType:
		return "There is no such version of Argon2"
	case Argon2ThreadsTooFew:
		return "Not enough threads"
	case Argon2ThreadsTooMany:
		return "Too many threads"
	case Argon2DecodingFail:
		return "Decoding failed"
	case Argon2VerifyMismatch:
		return "The password does not match the supplied hash"
	default:
		return "Unknown error code"
	}
}

func ValidateInputs(context Argon2Context) int {
	// Validate password (required param)
	pwdLen := uint32(len(context.Pwd))
	if 0 == pwdLen {
		return Argon2PwdPtrMismatch
	}

	if Argon2MinPwdLength > pwdLen {
		return Argon2PwdTooShort
	}

	if Argon2MaxPwdLength < pwdLen {
		return Argon2PwdTooLong
	}

	// Validate salt (required param)
	saltLen := uint32(len(context.Salt))
	if 0 == saltLen {
		return Argon2SaltPtrMismatch
	}

	if Argon2MinSaltLength > saltLen {
		return Argon2SaltTooShort
	}

	if Argon2MaxSaltLength < saltLen {
		return Argon2SaltTooLong
	}

	// Validate secret (optional param)
	if 0 == context.Secretlen {
		return Argon2SecretPtrMismatch
	} else {
		if Argon2MinSecret > context.Secretlen {
			return Argon2SecretTooShort
		}
		if Argon2MaxSecret < context.Secretlen {
			return Argon2SecretTooLong
		}
	}

	// Validate memory cost
	if Argon2MinMemory > context.Mcost {
		return Argon2MemoryTooLittle
	}

	if Argon2MaxMemory < uint64(context.Mcost) {
		return Argon2MemoryTooMuch
	}

	//if context.Mcost < 8*context.Lanes {
	if context.Mcost < 8*uint32(context.Threads) {
		return Argon2MemoryTooLittle
	}

	// Validate time cost
	if Argon2MinTime > context.Tcost {
		return Argon2TimeTooSmall
	}

	if Argon2MaxTime < context.Tcost {
		return Argon2TimeTooLarge
	}

	// Validate threads
	if Argon2MinThreads > uint32(context.Threads) {
		return Argon2ThreadsTooFew
	}

	if Argon2MaxThreads < uint32(context.Threads) {
		return Argon2ThreadsTooMany
	}

	return Argon2Ok
}

func Argon2Type2String(types Argon2Type, uppercase bool) string {
	switch types {
	case Argon2D:
		if uppercase {
			return "Argon2d"
		}
		return "argon2d"
	case Argon2I:
		if uppercase {
			return "Argon2i"
		}
		return "argon2i"
	case Argon2Id:
		if uppercase {
			return "Argon2id"
		}
		return "argon2id"
	}

	return ""
}

func Argon2Ctx(context Argon2Context, types Argon2Type) (string, error) {
	if ret := ValidateInputs(context); ret != Argon2Ok {
		return "", errors.New(Argon2ErrorMessage(ret))
	}

	switch types {
	case Argon2I, Argon2Id:
	default:
		return "", errors.New(Argon2ErrorMessage(Argon2IncorrectType))
	}

	var out strings.Builder
	switch types {
	case Argon2I:
		out.Write(argon2.Key([]byte(context.Pwd), []byte(context.Salt), context.Tcost, context.Mcost, context.Threads, context.Secretlen))
	case Argon2Id:
		out.Write(argon2.IDKey([]byte(context.Pwd), []byte(context.Salt), context.Tcost, context.Mcost, context.Threads, context.Secretlen))
	}

	ret := out.String()
	return ret, nil
}

func Argon2Compare(hash, pwd string) bool {
	ret := subtle.ConstantTimeCompare([]byte(hash), []byte(pwd)) == 1
	return ret
}

func Argon2VerifyCtx(context Argon2Context, hash string, types Argon2Type) error {
	ret, err := Argon2Ctx(context, types)
	if err != nil {
		return err
	}

	if Argon2Compare(hash, ret) {
		return nil
	}

	return errors.New(Argon2ErrorMessage(Argon2VerifyMismatch))
}

func DecodeString(context Argon2Context, encoded string, types Argon2Type) (Argon2Context, string, error) {
	vals := strings.Split(encoded, "$")
	if len(vals) != 6 {
		return Argon2Context{}, "", errors.New("v")
	}

	if vals[1] != Argon2Type2String(types, false) {
		return Argon2Context{}, "", errors.New(Argon2ErrorMessage(Argon2IncorrectType))
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return Argon2Context{}, "", errors.New("something wrong in argon 2 version")
	}
	if version != argon2.Version {
		return Argon2Context{}, "", errors.New("something wrong in argon 2 version")
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &context.Mcost, &context.Tcost, &context.Threads)
	if err != nil {
		return Argon2Context{}, "", errors.New("something wrong in argon 2 memory, time, and threads")
	}

	var sb strings.Builder

	salt, err := hex.DecodeString(vals[4])
	if err != nil {
		return Argon2Context{}, "", errors.New("something wrong in argon 2 salt")
	}

	sb.Write(salt)
	context.Salt = sb.String()
	sb.Reset()

	secret, err := hex.DecodeString(vals[5])
	if err != nil {
		return Argon2Context{}, "", errors.New("something wrong in argon 2 secret")
	}
	sb.Write(secret)
	ret := sb.String()
	context.Secretlen = uint32(len(ret))

	return context, ret, nil
}

func EncodeString(ctx Argon2Context, types Argon2Type, secret string) string {
	// Base64 encode the salt and hashed password.
	b64Salt := hex.EncodeToString([]byte(ctx.Salt))
	b64Hash := hex.EncodeToString([]byte(secret))
	typeString := Argon2Type2String(types, false)

	var out strings.Builder
	out.WriteString("$")
	out.WriteString(typeString)
	out.WriteString("$v=")
	out.WriteString(strconv.FormatUint(uint64(ctx.Version), 10))
	out.WriteString("$m=")
	out.WriteString(strconv.FormatUint(uint64(ctx.Mcost), 10))
	out.WriteString(",t=")
	out.WriteString(strconv.FormatUint(uint64(ctx.Tcost), 10))
	out.WriteString(",p=")
	out.WriteString(strconv.FormatUint(uint64(ctx.Threads), 10))
	out.WriteString("$")
	out.WriteString(b64Salt)
	out.WriteString("$")
	out.WriteString(b64Hash)

	ret := out.String()
	return ret
}

func Argon2Hash(password, salt string, time, memory uint32, threads uint8, keyLen uint32, version int, types Argon2Type) (string, error) {
	switch types {
	case Argon2I, Argon2Id:
	default:
		return "", errors.New(Argon2ErrorMessage(Argon2IncorrectType))
	}

	ctx := Argon2Context{
		Pwd:       password,
		Salt:      salt,
		Secretlen: keyLen,
		Mcost:     memory,
		Threads:   threads,
		Tcost:     time,
		Version:   version,
	}

	key, err := Argon2Ctx(ctx, types)
	if err != nil {
		return "", err
	}

	ret := EncodeString(ctx, types, key)
	return ret, nil
}

func Argon2Verify(encoded, pwd string, types Argon2Type) error {
	switch types {
	case Argon2I, Argon2Id:
	default:
		return errors.New(Argon2ErrorMessage(Argon2IncorrectType))
	}

	var ctx Argon2Context
	var encodedLen uint

	if int64(len(pwd)) > int64(Argon2MaxPwdLength) {
		return errors.New(Argon2ErrorMessage(Argon2PwdTooLong))
	}

	encodedLen = uint(len(encoded))
	if encodedLen == 0 {
		return errors.New(Argon2ErrorMessage(Argon2DecodingFail))
	}
	if encodedLen > Uint32Max {
		return errors.New(Argon2ErrorMessage(Argon2DecodingFail))
	}

	ctx.Pwd = pwd

	decodedContext, secret, err := DecodeString(ctx, encoded, types)
	if err != nil {
		return err
	}

	decodedContext.Pwd = ctx.Pwd
	if err = Argon2VerifyCtx(decodedContext, secret, types); err != nil {
		return err
	}

	return nil
}
