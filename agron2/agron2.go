package agron2

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonType int

const (
	Argon2D ArgonType = iota
	Argon2I
	Argon2Id
)

const Uint32Max = 4294967295

type Argon2Context struct {
	Pwd       []byte    // password array
	Pwdlen    uint32    // password length
	Salt      []byte    // salt string
	Saltlen   uint32    // salt len
	Secretlen uint32    // key length
	Mcost     uint32    // amount of memory requested (KB)
	Threads   uint8     // maximum number of threads or lanes
	Tcost     uint32    // number of passes
	Version   ArgonType // version number
}

const (
	Argon2Ok = iota
	Argon2OutputPtrNull
	Argon2OutputTooShort
	Argon2OutputTooLong
	Argon2PwdTooShort
	Argon2PwdTooLong
	Argon2SaltTooShort
	Argon2SaltTooLong
	Argon2AdTooShort
	Argon2AdTooLong
	Argon2SecretTooShort
	Argon2SecretTooLong
	Argon2TimeTooSmall
	Argon2TimeTooLarge
	Argon2MemoryTooLittle
	Argon2MemoryTooMuch
	Argon2LanesTooFew
	Argon2LanesTooMany
	Argon2PwdPtrMismatch
	Argon2SaltPtrMismatch
	Argon2SecretPtrMismatch
	Argon2AdPtrMismatch
	Argon2MemoryAllocationError
	Argon2FreeMemoryCbkNull
	Argon2AllocateMemoryCbkNull
	Argon2IncorrectParameter
	Argon2IncorrectType
	Argon2OutPtrMismatch
	Argon2ThreadsTooFew
	Argon2ThreadsTooMany
	Argon2MissingArgs
	Argon2EncodingFail
	Argon2DecodingFail
	Argon2ThreadFail
	Argon2DecodingLengthFail
	Argon2VerifyMismatch
)

func Argon2ErrorMessage(errorCode int) string {
	switch errorCode {
	case Argon2Ok:
		return "OK"
	case Argon2OutputPtrNull:
		return "Output pointer is NULL"
	case Argon2OutputTooShort:
		return "Output is too short"
	case Argon2OutputTooLong:
		return "Output is too long"
	case Argon2PwdTooShort:
		return "Password is too short"
	case Argon2PwdTooLong:
		return "Password is too long"
	case Argon2SaltTooShort:
		return "Salt is too short"
	case Argon2SaltTooLong:
		return "Salt is too long"
	case Argon2AdTooShort:
		return "Associated data is too short"
	case Argon2AdTooLong:
		return "Associated data is too long"
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
	case Argon2LanesTooFew:
		return "Too few lanes"
	case Argon2LanesTooMany:
		return "Too many lanes"
	case Argon2PwdPtrMismatch:
		return "Password pointer is NULL, but password length is not 0"
	case Argon2SaltPtrMismatch:
		return "Salt pointer is NULL, but salt length is not 0"
	case Argon2SecretPtrMismatch:
		return "Secret pointer is NULL, but secret length is not 0"
	case Argon2AdPtrMismatch:
		return "Associated data pointer is NULL, but ad length is not 0"
	case Argon2MemoryAllocationError:
		return "Memory allocation error"
	case Argon2FreeMemoryCbkNull:
		return "The free memory callback is NULL"
	case Argon2AllocateMemoryCbkNull:
		return "The allocate memory callback is NULL"
	case Argon2IncorrectParameter:
		return "Argon2_Context context is NULL"
	case Argon2IncorrectType:
		return "There is no such version of Argon2"
	case Argon2OutPtrMismatch:
		return "Output pointer mismatch"
	case Argon2ThreadsTooFew:
		return "Not enough threads"
	case Argon2ThreadsTooMany:
		return "Too many threads"
	case Argon2MissingArgs:
		return "Missing arguments"
	case Argon2EncodingFail:
		return "Encoding failed"
	case Argon2DecodingFail:
		return "Decoding failed"
	case Argon2ThreadFail:
		return "Threading failure"
	case Argon2DecodingLengthFail:
		return "Some of encoded parameters are too long or too short"
	case Argon2VerifyMismatch:
		return "The password does not match the supplied hash"
	default:
		return "Unknown error code"
	}
}

func Argon2Min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

const (
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

func ValidateInputs(context Argon2Context) int {
	// Validate salt (required param)
	if 0 == len(context.Salt) {
		if 0 != context.Saltlen {
			return Argon2SaltPtrMismatch
		}
	}

	if Argon2MinSaltLength > context.Saltlen {
		return Argon2SaltTooShort
	}

	if Argon2MaxSaltLength < context.Saltlen {
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

func Argon2Ctx(context Argon2Context, types ArgonType) ([]byte, error) {
	if ret := ValidateInputs(context); ret != Argon2Ok {
		return []byte{}, errors.New(Argon2ErrorMessage(ret))
	}

	var out []byte
	switch types {
	case Argon2I:
		out = argon2.Key(context.Pwd, context.Salt, context.Tcost, context.Mcost, context.Threads, context.Secretlen)
	case Argon2Id:
		out = argon2.IDKey(context.Pwd, context.Salt, context.Tcost, context.Mcost, context.Threads, context.Secretlen)
	}
	return out, nil
}

func Argon2Compare(hash, pwd []byte) bool {
	ret := subtle.ConstantTimeCompare(hash, pwd) == 1
	return ret
}

func Argon2VerifyCtx(context Argon2Context, hash []byte, types ArgonType) error {
	ret, err := Argon2Ctx(context, types)
	if err != nil {
		return err
	}

	if Argon2Compare(hash, ret) {
		return nil
	}

	return errors.New(Argon2ErrorMessage(Argon2VerifyMismatch))
}

func DecodeString(context Argon2Context, encoded []byte, types ArgonType) (Argon2Context, []byte, error) {
	vals := strings.Split(string(encoded[:]), "$")
	if len(vals) != 6 {
		return Argon2Context{}, []byte{}, errors.New("v")
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return Argon2Context{}, []byte{}, errors.New("ve")
	}
	if version != argon2.Version {
		return Argon2Context{}, []byte{}, errors.New("ver")
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &context.Mcost, &context.Tcost, &context.Threads)
	if err != nil {
		return Argon2Context{}, []byte{}, errors.New("scn")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return Argon2Context{}, []byte{}, errors.New("dcs")
	}
	context.Saltlen = uint32(len(salt))
	context.Salt = salt

	secret, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return Argon2Context{}, []byte{}, errors.New("dch")
	}
	context.Secretlen = uint32(len(secret))

	if err != nil {
		return Argon2Context{}, []byte{}, err
	}

	return context, secret, nil
}

func Argon2Verify(encoded []byte, pwd []byte, types ArgonType) error {
	var ctx Argon2Context
	var encodedLen uint

	if int64(len(pwd)) > int64(Argon2MaxPwdLength) {
		return errors.New(Argon2ErrorMessage(Argon2PwdTooLong))
	}

	if len(encoded) == 0 {
		return errors.New(Argon2ErrorMessage(Argon2DecodingFail))
	}

	encodedLen = uint(len(encoded))
	if encodedLen > Uint32Max {
		return errors.New(Argon2ErrorMessage(Argon2DecodingFail))
	}

	ctx.Pwd = pwd
	ctx.Pwdlen = uint32(len(pwd))

	decodedContext, secret, err := DecodeString(ctx, encoded, types)
	if err != nil {
		return err
	}

	decodedContext.Pwd = ctx.Pwd
	decodedContext.Pwdlen = ctx.Pwdlen

	if err = Argon2VerifyCtx(decodedContext, secret, types); err != nil {
		return err
	}

	return nil
}
