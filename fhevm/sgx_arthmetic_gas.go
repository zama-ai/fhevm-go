package fhevm

import "encoding/hex"

func sgxAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("sgxAdd/Sub RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error("sgxAdd/Sub RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}

	return environment.FhevmParams().GasCosts.SgxAddSub[lhs.fheUintType()]
}

func sgxMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	var lhs, rhs *verifiedCiphertext
	lhs, rhs, err := get2VerifiedOperands(environment, input)
	if err != nil {
		logger.Error("sgxMul RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error("sgxMul RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return 0
	}

	return environment.FhevmParams().GasCosts.SgxMul[lhs.fheUintType()]
}
