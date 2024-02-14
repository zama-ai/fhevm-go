package fhevm

import (
	"encoding/hex"
	"fmt"
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

func fheAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error("fheAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheAdd/Sub RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}

	return environment.FhevmParams().GasCosts.FheAddSub[lhs.fheUintType()]
}

func fheMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error("fheMul RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
		return environment.FhevmParams().GasCosts.FheMul[lhs.fheUintType()]
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMul RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		return environment.FhevmParams().GasCosts.FheScalarMul[lhs.fheUintType()]
	}
}

func fheLeRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error("comparison RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("comparison RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}
	return environment.FhevmParams().GasCosts.FheLe[lhs.fheUintType()]
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
	input = input[:minInt(65, len(input))]

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
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error("fheShift RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
		return environment.FhevmParams().GasCosts.FheShift[lhs.fheUintType()]
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShift RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		return environment.FhevmParams().GasCosts.FheScalarShift[lhs.fheUintType()]
	}
}

func fheShrRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of shl, because comparison costs are currently the same.
	return fheShlRequiredGas(environment, input)
}

func fheMinRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error("fheMin/Max RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
		return environment.FhevmParams().GasCosts.FheMinMax[lhs.fheUintType()]
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheMin/Max RequiredGas() scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		return environment.FhevmParams().GasCosts.FheScalarMinMax[lhs.fheUintType()]
	}
}

func fheMaxRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	// Implement in terms of min, because costs are currently the same.
	return fheMinRequiredGas(environment, input)
}

func fheNegRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

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
	return environment.FhevmParams().GasCosts.FheNeg[ct.fheUintType()]
}

func fheNotRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("fheNot input needs to contain one 256-bit sized value", "input", hex.EncodeToString(input))
		return 0
	}
	ct := getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("fheNot input not verified", "input", hex.EncodeToString(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheNot[ct.fheUintType()]
}

func fheDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		return environment.FhevmParams().GasCosts.FheScalarDiv[lhs.fheUintType()]
	}
}

func fheRemRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
		return environment.FhevmParams().GasCosts.FheScalarRem[lhs.fheUintType()]
	}
}

func fheBitAndRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

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
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error("Bitwise op RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}
	return environment.FhevmParams().GasCosts.FheBitwiseOp[lhs.fheUintType()]
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
	input = input[:minInt(1, len(input))]

	logger := environment.GetLogger()
	if len(input) != 1 || !isValidFheType(input[0]) {
		logger.Error("fheRand RequiredGas() input len must be at least 1 byte and be a valid FheUint type", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	t := FheUintType(input[0])
	return environment.FhevmParams().GasCosts.FheRand[t]
}

func parseRandUpperBoundInput(input []byte) (randType FheUintType, upperBound *uint256.Int, err error) {
	if len(input) != 33 || !isValidFheType(input[32]) {
		return FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() invalid input len or type")
	}
	randType = FheUintType(input[32])
	upperBound = uint256.NewInt(0)
	upperBound.SetBytes32(input)
	// For now, we only support bounds of up to 64 bits.
	if !upperBound.IsUint64() {
		return FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() only supports bounds up to 64 bits")
	}
	upperBound64 := upperBound.Uint64()
	oneBits := bits.OnesCount64(upperBound64)
	if oneBits != 1 {
		return FheUint8, nil, fmt.Errorf("parseRandUpperBoundInput() bound not a power of 2: %d", upperBound64)
	}
	return randType, upperBound, nil
}

func fheRandBoundedRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	randType, _, err := parseRandUpperBoundInput(input)
	if err != nil {
		logger.Error("fheRandBounded RequiredGas() bound error", "input", hex.EncodeToString(input), "err", err)
		return 0
	}
	return environment.FhevmParams().GasCosts.FheRand[randType]
}

func fheIfThenElseRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()
	first, second, third, err := get3VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("IfThenElse op RequiredGas() inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if first.fheUintType() != FheUint8 {
		logger.Error("IfThenElse op RequiredGas() invalid type for condition", "first", first.fheUintType())
		return 0
	}
	if second.fheUintType() != third.fheUintType() {
		logger.Error("IfThenElse op RequiredGas() operand type mismatch", "second", second.fheUintType(), "third", third.fheUintType())
		return 0
	}
	return environment.FhevmParams().GasCosts.FheIfThenElse[second.fheUintType()]
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
	input = input[:minInt(64, len(input))]

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
	return environment.FhevmParams().GasCosts.FheReencrypt[ct.fheUintType()]
}

func optimisticRequireRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

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
	if ct.fheUintType() != FheUint8 {
		logger.Error("optimisticRequire RequiredGas() ciphertext type is not FheUint8",
			"type", ct.fheUintType())
		return 0
	}
	if len(environment.FhevmData().optimisticRequires) == 0 {
		return environment.FhevmParams().GasCosts.FheOptRequire[FheUint8]
	}
	return environment.FhevmParams().GasCosts.FheOptRequireBitAnd[FheUint8]
}

func castRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	if len(input) != 33 {
		environment.GetLogger().Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}
	return environment.FhevmParams().GasCosts.FheCast
}

func decryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

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
	return environment.FhevmParams().GasCosts.FheDecrypt[ct.fheUintType()]
}

func fhePubKeyRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return environment.FhevmParams().GasCosts.FhePubKey
}

func trivialEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("trivialEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}
