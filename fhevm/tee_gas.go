package fhevm

import (
	"encoding/hex"
	"fmt"

	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func teeOperationGas(op string, environment EVMEnvironment, input []byte, gasCosts map[tfhe.FheUintType]uint64) uint64 {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error(fmt.Sprintf("%s can not detect if operator was meant to be scalar", op), "err", err, "input", hex.EncodeToString(input))
		return 0
	}

	var lhs, rhs *verifiedCiphertext

	if !isScalar {
		lhs, rhs, err = get2VerifiedOperands(environment, input)
		if err != nil {
			logger.Error(op, "RequiredGas() ciphertext inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			logger.Error(op, "RequiredGas() operand type mismatch", "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return 0
		}
	} else {
		lhs, _, err = getScalarOperands(environment, input)
		if err != nil {
			logger.Error("scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return 0
		}
	}

	return gasCosts[lhs.fheUintType()]
}
