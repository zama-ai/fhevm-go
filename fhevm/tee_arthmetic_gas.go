package fhevm

import "encoding/hex"

func teeAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("teeAdd/Sub RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error("teeAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}

	return environment.FhevmParams().GasCosts.TeeAddSub[lhs.fheUintType()]
}

func teeMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("teeMul RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error("teeMul RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}

	return environment.FhevmParams().GasCosts.TeeMul[lhs.fheUintType()]
}
