package fhevm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/crypto"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/nacl/box"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(environment *EVMEnvironment, input []byte) uint64 // RequiredGas calculates the contract gas use
	Run(environment *EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error)
}

var signatureFheAdd = makeKeccakSignature("fheAdd(uint256,uint256,bytes1)")
var signatureCast = makeKeccakSignature("cast(uint256,bytes1)")
var signatureDecrypt = makeKeccakSignature("decrypt(uint256)")
var signatureFhePubKey = makeKeccakSignature("fhePubKey(bytes1)")
var signatureTrivialEncrypt = makeKeccakSignature("trivialEncrypt(uint256,bytes1)")
var signatureFheSub = makeKeccakSignature("fheSub(uint256,uint256,bytes1)")
var signatureFheMul = makeKeccakSignature("fheMul(uint256,uint256,bytes1)")
var signatureFheLe = makeKeccakSignature("fheLe(uint256,uint256,bytes1)")
var signatureFheLt = makeKeccakSignature("fheLt(uint256,uint256,bytes1)")
var signatureFheEq = makeKeccakSignature("fheEq(uint256,uint256,bytes1)")
var signatureFheGe = makeKeccakSignature("fheGe(uint256,uint256,bytes1)")
var signatureFheGt = makeKeccakSignature("fheGt(uint256,uint256,bytes1)")
var signatureFheShl = makeKeccakSignature("fheShl(uint256,uint256,bytes1)")
var signatureFheShr = makeKeccakSignature("fheShr(uint256,uint256,bytes1)")
var signatureFheNe = makeKeccakSignature("fheNe(uint256,uint256,bytes1)")
var signatureFheMin = makeKeccakSignature("fheMin(uint256,uint256,bytes1)")
var signatureFheMax = makeKeccakSignature("fheMax(uint256,uint256,bytes1)")
var signatureFheNeg = makeKeccakSignature("fheNeg(uint256)")
var signatureFheNot = makeKeccakSignature("fheNot(uint256)")
var signatureFheDiv = makeKeccakSignature("fheDiv(uint256,uint256,bytes1)")
var signatureFheRem = makeKeccakSignature("fheRem(uint256,uint256,bytes1)")
var signatureFheBitAnd = makeKeccakSignature("fheBitAnd(uint256,uint256,bytes1)")
var signatureFheBitOr = makeKeccakSignature("fheBitOr(uint256,uint256,bytes1)")
var signatureFheBitXor = makeKeccakSignature("fheBitXor(uint256,uint256,bytes1)")
var signatureFheRand = makeKeccakSignature("fheRand(bytes1)")
var signatureVerifyCiphertext = makeKeccakSignature("verifyCiphertext(bytes)")
var signatureReencrypt = makeKeccakSignature("reencrypt(uint256,uint256)")
var signatureOptimisticRequire = makeKeccakSignature("optimisticRequire(uint256)")

func FheLibRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])
	switch signature {
	case signatureFheAdd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheAddSubRequiredGas(environment, bwCompatBytes)
	case signatureCast:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return castRequiredGas(environment, bwCompatBytes)
	case signatureDecrypt:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return decryptRequiredGas(environment, bwCompatBytes)
	case signatureFhePubKey:
		bwCompatBytes := input[4:minInt(5, len(input))]
		return fhePubKeyRequiredGas(environment, bwCompatBytes)
	case signatureTrivialEncrypt:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return trivialEncryptRequiredGas(environment, bwCompatBytes)
	case signatureFheSub:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheAddSubRequiredGas(environment, bwCompatBytes)
	case signatureFheMul:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMulRequiredGas(environment, bwCompatBytes)
	case signatureFheLe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLeRequiredGas(environment, bwCompatBytes)
	case signatureFheLt:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLtRequiredGas(environment, bwCompatBytes)
	case signatureFheEq:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheEqRequiredGas(environment, bwCompatBytes)
	case signatureFheGe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheGeRequiredGas(environment, bwCompatBytes)
	case signatureFheGt:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheGtRequiredGas(environment, bwCompatBytes)
	case signatureFheShl:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheShlRequiredGas(environment, bwCompatBytes)
	case signatureFheShr:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheShrRequiredGas(environment, bwCompatBytes)
	case signatureFheNe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheNeRequiredGas(environment, bwCompatBytes)
	case signatureFheMin:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMinRequiredGas(environment, bwCompatBytes)
	case signatureFheMax:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMaxRequiredGas(environment, bwCompatBytes)
	case signatureFheNeg:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return fheNegRequiredGas(environment, bwCompatBytes)
	case signatureFheNot:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return fheNotRequiredGas(environment, bwCompatBytes)
	case signatureFheDiv:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheDivRequiredGas(environment, bwCompatBytes)
	case signatureFheRem:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheRemRequiredGas(environment, bwCompatBytes)
	case signatureFheBitAnd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitAndRequiredGas(environment, bwCompatBytes)
	case signatureFheBitOr:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitOrRequiredGas(environment, bwCompatBytes)
	case signatureFheBitXor:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitXorRequiredGas(environment, bwCompatBytes)
	case signatureFheRand:
		bwCompatBytes := input[4:minInt(5, len(input))]
		return fheRandRequiredGas(environment, bwCompatBytes)
	case signatureVerifyCiphertext:
		bwCompatBytes := input[4:]
		return verifyCiphertextRequiredGas(environment, bwCompatBytes)
	case signatureReencrypt:
		bwCompatBytes := input[4:minInt(68, len(input))]
		return reencryptRequiredGas(environment, bwCompatBytes)
	case signatureOptimisticRequire:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return optimisticRequireRequiredGas(environment, bwCompatBytes)
	default:
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
}

func FheLibRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])
	switch signature {
	case signatureFheAdd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheAddRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureCast:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return castRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureDecrypt:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return decryptRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFhePubKey:
		bwCompatBytes := input[4:minInt(5, len(input))]
		precompileBytes, err := fhePubKeyRun(environment, caller, addr, bwCompatBytes, readOnly)
		if err != nil {
			return precompileBytes, err
		}
		// pad according to abi specification, first add offset to the dynamic bytes argument
		outputBytes := make([]byte, 32, len(precompileBytes)+32)
		outputBytes[31] = 0x20
		outputBytes = append(outputBytes, precompileBytes...)
		return padArrayTo32Multiple(outputBytes), nil
	case signatureTrivialEncrypt:
		bwCompatBytes := input[4:minInt(37, len(input))]
		return trivialEncryptRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheSub:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheSubRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheMul:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMulRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheLe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLeRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheLt:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheLtRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheEq:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheEqRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheGe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheGeRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheGt:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheGtRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheShl:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheShlRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheShr:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheShrRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheNe:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheNeRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheMin:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMinRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheMax:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheMaxRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheNeg:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return fheNegRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheNot:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return fheNotRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheDiv:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheDivRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheRem:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheRemRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheBitAnd:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitAndRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheBitOr:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitOrRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheBitXor:
		bwCompatBytes := input[4:minInt(69, len(input))]
		return fheBitXorRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureFheRand:
		bwCompatBytes := input[4:minInt(5, len(input))]
		return fheRandRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureVerifyCiphertext:
		// first 32 bytes of the payload is offset, then 32 bytes are size of byte array
		if len(input) <= 68 {
			err := errors.New("verifyCiphertext(bytes) must contain at least 68 bytes for selector, byte offset and size")
			logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		bytesPaddingSize := 32
		bytesSizeSlotSize := 32
		// read only last 4 bytes of padded number for byte array size
		sizeStart := 4 + bytesPaddingSize + bytesSizeSlotSize - 4
		sizeEnd := sizeStart + 4
		bytesSize := binary.BigEndian.Uint32(input[sizeStart:sizeEnd])
		bytesStart := 4 + bytesPaddingSize + bytesSizeSlotSize
		bytesEnd := bytesStart + int(bytesSize)
		bwCompatBytes := input[bytesStart:minInt(bytesEnd, len(input))]
		return verifyCiphertextRun(environment, caller, addr, bwCompatBytes, readOnly)
	case signatureReencrypt:
		bwCompatBytes := input[4:minInt(68, len(input))]
		precompileBytes, err := reencryptRun(environment, caller, addr, bwCompatBytes, readOnly)
		if err != nil {
			return precompileBytes, err
		}
		// pad according to abi specification, first add offset to the dynamic bytes argument
		outputBytes := make([]byte, 32, len(precompileBytes)+32)
		outputBytes[31] = 0x20
		outputBytes = append(outputBytes, precompileBytes...)
		return padArrayTo32Multiple(outputBytes), nil
	case signatureOptimisticRequire:
		bwCompatBytes := input[4:minInt(36, len(input))]
		return optimisticRequireRun(environment, caller, addr, bwCompatBytes, readOnly)
	default:
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
}

// Gas costs
func fheAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd/Sub RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd/Sub RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd/Sub RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}

	return environment.FhevmParams().GasCosts.FheAddSub[lhs.ciphertext.fheUintType]
}

func fheMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheMul RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheMul[lhs.ciphertext.fheUintType]
}

func fheLeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("comparison RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("comparison RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheLe[lhs.ciphertext.fheUintType]
}

func fheLtRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because le and lt costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheEqRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheGeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheGtRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheNeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of le, because comparison costs are currently the same.
	return fheLeRequiredGas(environment, input)
}

func fheShlRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShift RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheShift RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheShift RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShift RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheShift[lhs.ciphertext.fheUintType]
}

func fheShrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of shl, because comparison costs are currently the same.
	return fheShlRequiredGas(environment, input)
}

func fheMinRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMin/Max RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs, rhs *verifiedCiphertext
	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMin/Max RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			logger.Error("fheMin/Max RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMin/Max RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheMinMax[lhs.ciphertext.fheUintType]
}

func fheMaxRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of min, because costs are currently the same.
	return fheMinRequiredGas(environment, input)
}

func fheNegRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("fheNeg input needs to contain one 256-bit sized value", "input", hex.EncodeToString(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("fheNeg input not verified", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheNegNot[ct.ciphertext.fheUintType]
}

func fheNotRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of neg, because costs are currently the same.
	return fheNegRequiredGas(environment, input)
}

func fheDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheDiv RequiredGas() cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs *verifiedCiphertext
	if !isScalar {
		logger.Error("fheDiv RequiredGas() only scalar in division is supported, two ciphertexts received", "input", hex.EncodeToString(input))
		return 0
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheDiv RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheDiv[lhs.ciphertext.fheUintType]
}

func fheRemRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRem RequiredGas() cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	var lhs *verifiedCiphertext
	if !isScalar {
		logger.Error("fheRem RequiredGas() only scalar in division is supported, two ciphertexts received", "input", hex.EncodeToString(input))
		return 0
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRem RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheRem[lhs.ciphertext.fheUintType]
}

func fheBitAndRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("Bitwise op RequiredGas() can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return 0
	}

	if isScalar {
		msg := "Bitwise op RequiredGas() scalar op not supported"
		logger.Error(msg)
		return 0
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("Bitwise op RequiredGas() inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
		logger.Error("Bitwise op RequiredGas() operand type mismatch", "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
		return 0
	}
	return environment.FhevmParams().GasCosts.FheBitwiseOp[lhs.ciphertext.fheUintType]
}

func fheBitOrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of bitAnd, because bitwise op costs are currently the same.
	return fheBitAndRequiredGas(environment, input)
}

func fheBitXorRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of bitAnd, because bitwise op costs are currently the same.
	return fheBitAndRequiredGas(environment, input)
}

func fheRandRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 1 || !isValidType(input[0]) {
		logger.Error("fheRand RequiredGas() input len must be at least 1 byte and be a valid FheUint type", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	t := FheUintType(input[0])
	return environment.FhevmParams().GasCosts.FheRand[t]
}

func verifyCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	if len(input) <= 1 {
		environment.GetLogger().Error(
			"verifyCiphertext RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	ctType := FheUintType(input[len(input)-1])
	return environment.FhevmParams().GasCosts.FheVerify[ctType]
}

func reencryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 64 {
		logger.Error("reencrypt RequiredGas() input len must be 64 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("reencrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheReencrypt[ct.ciphertext.fheUintType]
}

func optimisticRequireRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("optimisticRequire RequiredGas() input len must be 32 bytes",
			"input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("optimisticRequire RequiredGas() input doesn't point to verified ciphertext",
			"input", hex.EncodeToString(input))
		return 0
	}
	if ct.ciphertext.fheUintType != FheUint8 {
		logger.Error("optimisticRequire RequiredGas() ciphertext type is not FheUint8",
			"type", ct.ciphertext.fheUintType)
		return 0
	}
	if len(environment.FhevmData().optimisticRequires) == 0 {
		return environment.FhevmParams().GasCosts.FheOptRequire[FheUint8]
	}
	return environment.FhevmParams().GasCosts.FheOptRequireBitAnd[FheUint8]
}

func castRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	if len(input) != 33 {
		environment.GetLogger().Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheCast
}

func decryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("decrypt RequiredGas() input len must be 32 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		logger.Error("decrypt RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheDecrypt[ct.ciphertext.fheUintType]
}

func fhePubKeyRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return environment.FhevmParams().GasCosts.FhePubKey
}

func trivialEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("trivialEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}

// Implementations
func fheAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheAdd operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.add(rhs.ciphertext)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheAdd success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarAdd(rhs.Uint64())
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheAdd scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheSub can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheSub inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheSub operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.sub(rhs.ciphertext)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheSub success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheSub scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarSub(rhs.Uint64())
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheSub scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheMul operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.mul(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMul success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarMul(rhs.Uint64())
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMul scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheLe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheLe operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.le(rhs.ciphertext)
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLe success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheLe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarLe(rhs.Uint64())
		if err != nil {
			logger.Error("fheLe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLe scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheLt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheLt inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheLt operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.lt(rhs.ciphertext)
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLt success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheLt scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarLt(rhs.Uint64())
		if err != nil {
			logger.Error("fheLt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheLt scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheEq can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheEq inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheEq operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.eq(rhs.ciphertext)
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheEq success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheEq scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarEq(rhs.Uint64())
		if err != nil {
			logger.Error("fheEq failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheEq scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheGe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheGe operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.ge(rhs.ciphertext)
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheGe success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheGe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarGe(rhs.Uint64())
		if err != nil {
			logger.Error("fheGe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheGe scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheGt can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheGt inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheGt operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.gt(rhs.ciphertext)
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheGt success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheGt scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarGt(rhs.Uint64())
		if err != nil {
			logger.Error("fheGt failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheGt scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheShl inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.shl(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheShl success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShl scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarShl(rhs.Uint64())
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheShl scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheShr inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheShr operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.shr(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheShr success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShr scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarShr(rhs.Uint64())
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheShr scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheNe can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheNe inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheNe operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.ne(rhs.ciphertext)
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheNe success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheNe scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarNe(rhs.Uint64())
		if err != nil {
			logger.Error("fheNe failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheNe scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMin can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMin inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheMin operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.min(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMin success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMin scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarMin(rhs.Uint64())
		if err != nil {
			logger.Error("fheMin failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMin scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMax can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error("fheMax inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
			msg := "fheMax operand type mismatch"
			logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.max(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMax success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMax scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarMax(rhs.Uint64())
		if err != nil {
			logger.Error("fheMax failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheMax scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNeg input not verified"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.ciphertext.fheUintType), nil
	}

	result, err := ct.ciphertext.neg()
	if err != nil {
		logger.Error("fheNeg failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.getHash()
	logger.Info("fheNeg success", "ct", ct.ciphertext.getHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNot input not verified"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.ciphertext.fheUintType), nil
	}

	result, err := ct.ciphertext.not()
	if err != nil {
		logger.Error("fheNot failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.getHash()
	logger.Info("fheNot success", "ct", ct.ciphertext.getHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheDiv cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheDiv supports only scalar input operation, two ciphertexts received")
		logger.Error("fheDiv supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheDiv scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarDiv(rhs.Uint64())
		if err != nil {
			logger.Error("fheDiv failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheDiv scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRem cannot detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		err = errors.New("fheRem supports only scalar input operation, two ciphertexts received")
		logger.Error("fheRem supports only scalar input operation, two ciphertexts received", "input", hex.EncodeToString(input))
		return nil, err
	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRem scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
		}

		result, err := lhs.ciphertext.scalarRem(rhs.Uint64())
		if err != nil {
			logger.Error("fheRem failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.getHash()
		logger.Info("fheRem scalar success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitAnd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitAnd scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("fheBitAnd inputs not verified", "err", err)
		return nil, err
	}

	if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
		msg := "fheBitAnd operand type mismatch"
		logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
	}

	result, err := lhs.ciphertext.bitand(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitAnd failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.getHash()
	logger.Info("fheBitAnd success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitOr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitOr scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("fheBitOr inputs not verified", "err", err)
		return nil, err
	}

	if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
		msg := "fheBitOr operand type mismatch"
		logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
	}

	result, err := lhs.ciphertext.bitor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitOr failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.getHash()
	logger.Info("fheBitOr success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitXor can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitXor scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("fheBitXor inputs not verified", "err", err)
		return nil, err
	}

	if lhs.ciphertext.fheUintType != rhs.ciphertext.fheUintType {
		msg := "fheBitXor operand type mismatch"
		logger.Error(msg, "lhs", lhs.ciphertext.fheUintType, "rhs", rhs.ciphertext.fheUintType)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.ciphertext.fheUintType), nil
	}

	result, err := lhs.ciphertext.bitxor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitXor failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.getHash()
	logger.Info("fheBitXor success", "lhs", lhs.ciphertext.getHash().Hex(), "rhs", rhs.ciphertext.getHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

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

func fheRandRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRand cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 1 || !isValidType(input[0]) {
		msg := "fheRand input len must be at least 1 byte and be a valid FheUint type"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	t := FheUintType(input[0])
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() {
		return importRandomCiphertext(environment, t), nil
	}

	// Get the RNG nonce.
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(caller)
	currentRngNonceBytes := environment.GetState(protectedStorage, rngNonceKey).Bytes()

	// Increment the RNG nonce by 1.
	nextRngNonce := newInt(currentRngNonceBytes)
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
	// The RNG nonce bytes are of size chacha20.NonceSizeX, which is assumed to be 24 bytes (see init() above).
	// Since uint256.Int.z[0] is the least significant byte and since uint256.Int.Bytes32() serializes
	// in order of z[3], z[2], z[1], z[0], we want to essentially ignore the first byte, i.e. z[3], because
	// it will always be 0 as the nonce size is 24.
	cipher, err := chacha20.NewUnauthenticatedCipher(seed.Bytes(), currentRngNonceBytes[32-chacha20.NonceSizeX:32])
	if err != nil {
		return nil, err
	}

	// XOR a byte array of 0s with the stream from the cipher and receive the result in the same array.
	randBytes := make([]byte, 8)
	cipher.XORKeyStream(randBytes, randBytes)

	// Trivially encrypt the random integer.
	randUint64 := binary.BigEndian.Uint64(randBytes)
	randCt := new(tfheCiphertext)
	randBigInt := big.NewInt(0)
	randBigInt.SetUint64(randUint64)
	randCt.trivialEncrypt(*randBigInt, t)
	importCiphertext(environment, randCt)

	if err != nil {
		return nil, err
	}
	ctHash := randCt.getHash()
	return ctHash[:], nil
}

func verifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) <= 1 {
		msg := "verifyCiphertext Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ctBytes := input[:len(input)-1]
	ctTypeByte := input[len(input)-1]
	if !isValidType(ctTypeByte) {
		msg := "verifyCiphertext Run() ciphertext type is invalid"
		logger.Error(msg, "type", ctTypeByte)
		return nil, errors.New(msg)
	}
	ctType := FheUintType(ctTypeByte)

	expectedSize, found := compactFheCiphertextSize[ctType]
	if !found || expectedSize != uint(len(ctBytes)) {
		msg := "verifyCiphertext Run() compact ciphertext size is invalid"
		logger.Error(msg, "type", ctTypeByte, "size", len(ctBytes), "expectedSize", expectedSize)
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ctType), nil
	}

	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ctBytes, ctType)
	if err != nil {
		logger.Error("verifyCiphertext failed to deserialize input ciphertext",
			"err", err,
			"len", len(ctBytes),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
		return nil, err
	}
	ctHash := ct.getHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("verifyCiphertext success",
			"ctHash", ctHash.Hex(),
			"ctBytes64", hex.EncodeToString(ctBytes[:minInt(len(ctBytes), 64)]))
	}
	return ctHash.Bytes(), nil
}

func classicalPublicKeyEncrypt(value *big.Int, userPublicKey []byte) ([]byte, error) {
	encrypted, err := box.SealAnonymous(nil, value.Bytes(), (*[32]byte)(userPublicKey), rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func encryptToUserKey(value *big.Int, pubKey []byte) ([]byte, error) {
	ct, err := classicalPublicKeyEncrypt(value, pubKey)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func reencryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if !environment.IsEthCall() {
		msg := "reencrypt only supported on EthCall"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 64 {
		msg := "reencrypt input len must be 64 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct != nil {
		// Make sure we don't decrypt before any optimistic requires are checked.
		optReqResult, optReqErr := evaluateRemainingOptimisticRequires(environment)
		if optReqErr != nil {
			return nil, optReqErr
		} else if !optReqResult {
			return nil, ErrExecutionReverted
		}
		decryptedValue, err := ct.ciphertext.decrypt()
		if err != nil {
			logger.Error("reencrypt decryption failed", "err", err)
			return nil, err
		}
		pubKey := input[32:64]
		reencryptedValue, err := encryptToUserKey(&decryptedValue, pubKey)
		if err != nil {
			logger.Error("reencrypt failed to encrypt to user key", "err", err)
			return nil, err
		}
		logger.Info("reencrypt success", "input", hex.EncodeToString(input), "callerAddr", caller)
		return toEVMBytes(reencryptedValue), nil
	}
	msg := "reencrypt unverified ciphertext handle"
	logger.Error(msg, "input", hex.EncodeToString(input))
	return nil, errors.New(msg)
}

func optimisticRequireRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) != 32 {
		msg := "optimisticRequire input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "optimisticRequire unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	// If we are doing gas estimation, don't do anything as we would assume all requires are true.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return nil, nil
	}
	if ct.ciphertext.fheUintType != FheUint8 {
		msg := "optimisticRequire ciphertext type is not FheUint8"
		logger.Error(msg, "type", ct.ciphertext.fheUintType)
		return nil, errors.New(msg)
	}
	environment.FhevmData().optimisticRequires = append(environment.FhevmData().optimisticRequires, ct.ciphertext)
	return nil, nil
}

func decryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	// if not gas estimation and not view function fail if decryptions are disabled in transactions
	if environment.IsCommitting() && !environment.IsEthCall() && environment.FhevmParams().DisableDecryptionsInTransaction {
		msg := "decryptions during transaction are disabled"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	if len(input) != 32 {
		msg := "decrypt input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input))
	if ct == nil {
		msg := "decrypt unverified handle"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	// If we are doing gas estimation, skip decryption and make sure we return the maximum possible value.
	// We need that, because non-zero bytes cost more than zero bytes in some contexts (e.g. SSTORE or memory operations).
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return bytes.Repeat([]byte{0xFF}, 32), nil
	}
	// Make sure we don't decrypt before any optimistic requires are checked.
	optReqResult, optReqErr := evaluateRemainingOptimisticRequires(environment)
	if optReqErr != nil {
		return nil, optReqErr
	} else if !optReqResult {
		return nil, ErrExecutionReverted
	}
	plaintext, err := decryptValue(ct.ciphertext)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}
	// Always return a 32-byte big-endian integer.
	ret := make([]byte, 32)
	bigIntValue := big.NewInt(0)
	bigIntValue.SetUint64(plaintext)
	bigIntValue.FillBytes(ret)
	return ret, nil
}

func decryptValue(ct *tfheCiphertext) (uint64, error) {
	v, err := ct.decrypt()
	return v.Uint64(), err
}

// If there are optimistic requires, check them by doing bitwise AND on all of them.
// That works, because we assume their values are either 0 or 1. If there is at least
// one 0, the result will be 0 (false).
func evaluateRemainingOptimisticRequires(environment EVMEnvironment) (bool, error) {
	requires := environment.FhevmData().optimisticRequires
	len := len(requires)
	defer func() { environment.FhevmData().optimisticRequires = make([]*tfheCiphertext, 0) }()
	if len != 0 {
		var cumulative *tfheCiphertext = requires[0]
		var err error
		for i := 1; i < len; i++ {
			cumulative, err = cumulative.bitand(requires[i])
			if err != nil {
				environment.GetLogger().Error("evaluateRemainingOptimisticRequires bitand failed", "err", err)
				return false, err
			}
		}
		result, err := decryptValue(cumulative)
		return result != 0, err
	}
	return true, nil
}

func castRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "cast Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("cast input not verified")
		return nil, errors.New("unverified ciphertext handle")
	}

	if !isValidType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := FheUintType(input[32])

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, castToType), nil
	}

	res, err := ct.ciphertext.castTo(castToType)
	if err != nil {
		msg := "cast Run() error casting ciphertext to"
		logger.Error(msg, "type", castToType)
		return nil, errors.New(msg)
	}

	resHash := res.getHash()

	importCiphertext(environment, res)
	if environment.IsCommitting() {
		logger.Info("cast success",
			"ctHash", resHash.Hex(),
		)
	}

	return resHash.Bytes(), nil
}

var fhePubKeyHashPrecompile = common.BytesToAddress([]byte{93})
var fhePubKeyHashSlot = common.Hash{}

func fhePubKeyRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	existing := environment.GetState(fhePubKeyHashPrecompile, fhePubKeyHashSlot)
	if existing != pksHash {
		msg := "fhePubKey FHE public key hash doesn't match one stored in state"
		environment.GetLogger().Error(msg, "existing", existing.Hex(), "pksHash", pksHash.Hex())
		return nil, errors.New(msg)
	}
	// serialize public key
	pksBytes, err := serializePublicKey(pks)
	if err != nil {
		return nil, err
	}
	// If we have a single byte with the value of 1, return as an EVM array. Otherwise, returh the raw bytes.
	if len(input) == 1 && input[0] == 1 {
		return toEVMBytes(pksBytes), nil
	} else {
		return pksBytes, nil
	}
}

func trivialEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "trivialEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := FheUintType(input[32])

	ct := new(tfheCiphertext).trivialEncrypt(valueToEncrypt, encryptToType)

	ctHash := ct.getHash()
	importCiphertext(environment, ct)
	if environment.IsCommitting() {
		logger.Info("trivialEncrypt success",
			"ctHash", ctHash.Hex(),
			"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}
