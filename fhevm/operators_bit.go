package fhevm

import (
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func fheShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheShl inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Shl(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShl success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheShl scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarShl(rhs)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShl scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheShr inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheShr operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Shr(rhs.ciphertext)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShr success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheShr scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarShr(rhs)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheShr scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}


func fheRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheShl inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Rotl(rhs.ciphertext)
		if err != nil {
			logger.Error("fheRotl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRotl success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheRotl scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarRotl(rhs)
		if err != nil {
			logger.Error("fheRotl failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRotl scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRotr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, err := get2VerifiedOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if err != nil {
			logger.Error("fheRotr inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		if lhs.fheUintType() != rhs.fheUintType() {
			msg := "fheRotr operand type mismatch"
			logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.Rotr(rhs.ciphertext)
		if err != nil {
			logger.Error("fheRotr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRotr success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, err := getScalarOperands(environment, input)
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))
		if err != nil {
			logger.Error("fheRotr scalar inputs not verified", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return importRandomCiphertext(environment, lhs.fheUintType()), nil
		}

		result, err := lhs.ciphertext.ScalarRotr(rhs)
		if err != nil {
			logger.Error("fheRotr failed", "err", err)
			return nil, err
		}
		importCiphertext(environment, result)

		resultHash := result.GetHash()
		logger.Info("fheRotr scalar success", "lhs", lhs.hash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

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
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.fheUintType()), nil
	}

	result, err := ct.ciphertext.Neg()
	if err != nil {
		logger.Error("fheNeg failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheNeg success", "ct", ct.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

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
	otelDescribeOperandsFheTypes(runSpan, ct.fheUintType())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, ct.fheUintType()), nil
	}

	result, err := ct.ciphertext.Not()
	if err != nil {
		logger.Error("fheNot failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheNot success", "ct", ct.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

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
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitAnd inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitAnd operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitand(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitAnd failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitAnd success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

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
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitOr inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitOr operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitOr failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitOr success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

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
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error("fheBitXor inputs not verified", "err", err)
		return nil, err
	}

	if lhs.fheUintType() != rhs.fheUintType() {
		msg := "fheBitXor operand type mismatch"
		logger.Error(msg, "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	result, err := lhs.ciphertext.Bitxor(rhs.ciphertext)
	if err != nil {
		logger.Error("fheBitXor failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, result)

	resultHash := result.GetHash()
	logger.Info("fheBitXor success", "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}
