package fhevm

import (
	"encoding/hex"
	"fmt"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

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
	return environment.FhevmParams().GasCosts.FheEq[lhs.fheUintType()]
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
	return fheEqRequiredGas(environment, input)
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

func fheIfThenElseRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()
	first, second, third, err := get3VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("IfThenElse op RequiredGas() inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if first.fheUintType() != tfhe.FheBool {
		logger.Error("IfThenElse op RequiredGas() invalid type for condition", "first", first.fheUintType())
		return 0
	}
	if second.fheUintType() != third.fheUintType() {
		logger.Error("IfThenElse op RequiredGas() operand type mismatch", "second", second.fheUintType(), "third", third.fheUintType())
		return 0
	}
	return environment.FhevmParams().GasCosts.FheIfThenElse[second.fheUintType()]
}

func fheArrayEqRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()

	unpacked, err := arrayEqMethod.Inputs.UnpackValues(input)
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to unpack input"
		logger.Error(msg, "err", err)
		return 0
	}

	if len(unpacked) != 2 {
		err := fmt.Errorf("fheArrayEqRun RequiredGas() unexpected unpacked len: %d", len(unpacked))
		logger.Error(err.Error())
		return 0
	}

	lhs, err := getVerifiedCiphertexts(environment, unpacked[0])
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to get lhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return 0
	}

	rhs, err := getVerifiedCiphertexts(environment, unpacked[1])
	if err != nil {
		msg := "fheArrayEqRun RequiredGas() failed to get rhs to verified ciphertexts"
		logger.Error(msg, "err", err)
		return 0
	}

	if len(lhs) != len(rhs) || (len(lhs) == 0 && len(rhs) == 0) {
		return environment.FhevmParams().GasCosts.FheTrivialEncrypt[tfhe.FheBool]
	}

	numElements := len(lhs)
	elementType := lhs[0].Type()
	// TODO: tie to supported types in tfhe.TfheCiphertext.EqArray()
	if elementType != tfhe.FheUint4 && elementType != tfhe.FheUint8 && elementType != tfhe.FheUint16 && elementType != tfhe.FheUint32 && elementType != tfhe.FheUint64 {
		return 0
	}
	for i := range lhs {
		if lhs[i].Type() != elementType || rhs[i].Type() != elementType {
			return 0
		}
	}

	numBits := elementType.NumBits() * uint(numElements)
	if numBits <= 4 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint4]
	} else if numBits <= 8 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint8]
	} else if numBits <= 16 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint16]
	} else if numBits <= 32 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint32]
	} else if numBits <= 64 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint64]
	} else if numBits <= 160 {
		return environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint160]
	} else {
		return (environment.FhevmParams().GasCosts.FheEq[tfhe.FheUint160] + environment.FhevmParams().GasCosts.FheArrayEqBigArrayFactor) * (uint64(numBits) / 160)
	}
}
