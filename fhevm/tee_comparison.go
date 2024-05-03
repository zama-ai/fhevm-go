package fhevm

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

func teeLeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a <= b)
	}, "teeLeRun")
}

func teeLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a < b)
	}, "teeLtRun")
}

func teeEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doEqNeOp(environment, caller, input, runSpan, func(a, b *big.Int) bool {
		if a.Cmp(b) == 0 {
			return true
		} else {
			return false
		}
	}, "teeEqRun")
}

func teeGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a >= b)
	}, "teeGeRun")
}

func teeGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a > b)
	}, "teeGtRun")
}

func teeNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doEqNeOp(environment, caller, input, runSpan, func(a, b *big.Int) bool {
		if a.Cmp(b) != 0 {
			return true
		} else {
			return false
		}
	}, "teeNeRun")
}

func teeMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		if a >= b {
			return b
		} else {
			return a
		}
	}, "teeMinRun")
}

func teeMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		if a >= b {
			return a
		} else {
			return b
		}
	}, "teeMaxRun")
}

func teeSelectRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	p1, p2, _, h1, h2, h3, err := extract3Operands("teeSelect", environment, input, runSpan)
	if err != nil {
		logger.Error("teeSelect", "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, p2.FheUintType), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if p2.FheUintType == tfhe.FheUint128 {
		// panic("TODO implement me")
		logger.Error("unsupported FheUintType: %s", p2.FheUintType)
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert th
	// result back to the FheUintType.
	var result big.Int
	s := big.NewInt(0).SetBytes(p2.Value)
	t := big.NewInt(0).SetBytes(p2.Value)
	if p1.Value[0] == 1 {
		result.Set(s)
	} else {
		result.Set(t)
	}
	resultBz, err := marshalTfheType(&result, p2.FheUintType)
	if err != nil {
		return nil, err
	}

	teePlaintext := tee.NewTeePlaintext(resultBz, p2.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error("teeSelect", "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", "teeSelect"), "h1", h1.hash().Hex(), "h2", h2.hash().Hex(), "h3", h3.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}
