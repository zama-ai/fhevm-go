package fhevm

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func sgxAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheAdd operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l + r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.fheUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("fheAdd failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxAdd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}

func sgxSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheAdd operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l - r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.fheUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("fheAdd failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxMul success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}

func sgxMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheMul operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l * r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.fheUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("fheAdd failed", "err", err)
		return nil, err
	}
	return result, nil
}

func sgxDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := getScalarOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
	if err != nil {
		logger.Error("fheDiv scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	lb, err := decryptRun(environment, caller, addr, input[0:32], readOnly, runSpan)
	rb, err := decryptRun(environment, caller, addr, input[32:64], readOnly, runSpan)

	l := big.NewInt(0).SetBytes(lb).Uint64()
	r := big.NewInt(0).SetBytes(rb).Uint64()

	result_plaintext := l - r

	result_plaintext_byte := make([]byte, 33)
	result_byte := big.NewInt(0)
	result_byte.SetUint64(result_plaintext)
	result_byte.FillBytes(result_plaintext_byte)
	result_plaintext_byte[32] = byte(lhs.fheUintType())

	result, err := trivialEncryptRun(environment, caller, addr, result_plaintext_byte, readOnly, runSpan)

	if err != nil {
		logger.Error("fheAdd failed", "err", err)
		return nil, err
	}

	// logger.Info("sgxDiv success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", result.Hex())
	return result, nil
}

func fheAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheAdd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheAdd inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheAdd operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Add(rhs.ciphertext)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheAdd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheAdd scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarAdd(rhs)
		if err != nil {
			logger.Error("fheAdd failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheAdd scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheSub can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheSub inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheSub operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Sub(rhs.ciphertext)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheSub success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheSub scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarSub(rhs)
		if err != nil {
			logger.Error("fheSub failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheSub scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheMul can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheMul inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheMul operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Mul(rhs.ciphertext)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMul success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheMul scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarMul(rhs)
		if err != nil {
			logger.Error("fheMul failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheMul scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

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
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheDiv scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarDiv(rhs)
		if err != nil {
			logger.Error("fheDiv failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheDiv scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

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
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheRem scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarRem(rhs)
		if err != nil {
			logger.Error("fheRem failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRem scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}
