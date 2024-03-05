package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
)

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
