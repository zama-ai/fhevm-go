package fhevm

import (
	"encoding/hex"

	"github.com/zama-ai/fhevm-go/pkg/tfhe"
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
