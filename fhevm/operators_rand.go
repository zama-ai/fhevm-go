package fhevm

import (
	"encoding/hex"
	"errors"
	"math/bits"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/fhevm/crypto"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/chacha20"
)

var globalRngSeed []byte

var rngNonceKey [32]byte = uint256.NewInt(0).Bytes32()

func init() {
	if chacha20.NonceSizeX != 24 {
		panic("expected 24 bytes for NonceSizeX")
	}

	// TODO: Since the current implementation is not FHE-based and, hence, not private,
	// we just initialize the global seed with non-random public data. We will change
	// that once the FHE version is available.
	globalRngSeed = make([]byte, chacha20.KeySize)
	for i := range globalRngSeed {
		globalRngSeed[i] = byte(1 + i)
	}
}

// Applies the upperBound (if set) to the rand value and returns the result.
// bitsInRand is the amount of random bits that are contained in rand.
// bitsInRand and upperBound must be powers of 2.
func applyUpperBound(rand uint64, bitsInRand int, upperBound *uint64) uint64 {
	if upperBound == nil {
		return rand
	} else if *upperBound == 0 {
		panic("sliceRandom called with upperBound of 0")
	}
	// Len64() returns the amount of bits needed to represent upperBound. Subtract 1 to get the
	// amount of bits requested by the given upperBound as we want to return a value in the [0, upperBound) range.
	// Note that upperBound is assumed to be a power of 2.
	//
	// For example, if upperBound = 128, then bits = 8 - 1 = 7 random bits to be returned.
	// To get that amount of random bits from rand, subtract bits from bitsInRand, i.e.
	// shift = 32 - 7 = 25. Shifting rand 25 positions would leave 7 of its random bits.
	bits := bits.Len64(*upperBound) - 1
	shift := bitsInRand - bits
	// If the shift ends up negative or 0, just return rand without any shifts.
	if shift <= 0 {
		return rand
	}
	return rand >> shift
}

func generateRandom(environment EVMEnvironment, caller common.Address, resultType tfhe.FheUintType, numberOfBits uint64) ([]byte, error) {
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() {
		return insertRandomCiphertext(environment, resultType), nil
	}

	// Get the RNG nonce.
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(caller)
	currentRngNonceBytes := environment.GetState(protectedStorage, rngNonceKey).Bytes()

	// Increment the RNG nonce by 1.
	nextRngNonce := uint256.NewInt(0).SetBytes(currentRngNonceBytes)
	nextRngNonce = nextRngNonce.AddUint64(nextRngNonce, 1)
	environment.SetState(protectedStorage, rngNonceKey, nextRngNonce.Bytes32())

	// Compute the seed and use it to create a new cipher.
	hasher := crypto.NewKeccakState()
	hasher.Write(globalRngSeed)
	hasher.Write(caller.Bytes())
	seed := common.Hash{}
	_, err := hasher.Read(seed[:])
	if err != nil {
		return nil, err
	}

	randCt, err := tfhe.GenerateObliviousPseudoRandom(resultType, *(*uint64)(unsafe.Pointer(&seed.Bytes()[0])), numberOfBits)

	if err != nil {
		return nil, err
	}
	
	insertCiphertextToMemory(environment, randCt)

	ctHash := randCt.GetHash()
	return ctHash[:], nil
}

func fheRandRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRand cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 1 || !tfhe.IsValidFheType(input[0]) {
		msg := "fheRand input len must be at least 1 byte and be a valid FheUint type"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	resultType := tfhe.FheUintType(input[0])
	otelDescribeOperandsFheTypes(runSpan, resultType)
	var noUpperBound uint64 = uint64(resultType.NumBits())
	return generateRandom(environment, caller, resultType, noUpperBound)
}

func fheRandBoundedRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRandBoundedRun cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	randType, bound, err := parseRandUpperBoundInput(input)
	otelDescribeOperandsFheTypes(runSpan, randType)
	if err != nil {
		msg := "fheRandBounded bound error"
		logger.Error(msg, "input", hex.EncodeToString(input), "err", err)
		return nil, errors.New(msg)
	}
	bound64 := bound.Uint64()
	numberOfBits := uint64(1);
	for bound64 > uint64(1) {
		bound64 = bound64 / uint64(2);
		numberOfBits++;
	}
	return generateRandom(environment, caller, randType, numberOfBits)
}
