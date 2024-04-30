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
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a <= b)
	}, "teeLeRun")
}

func teeLtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a < b)
	}, "teeLtRun")
}

func teeEqRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a == b)
	}, "teeEqRun")
}

func teeGeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a >= b)
	}, "teeGeRun")
}

func teeGtRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a > b)
	}, "teeGtRun")
}

func teeNeRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return boolToUint64(a != b)
	}, "teeNeRun")
}

func teeMinRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		if a >= b {
			return b
		} else {
			return a
		}
	}, "teeMinRun")
}

func teeMaxRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOperationGeneric(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		if a >= b {
			return a
		} else {
			return b
		}
	}, "teeMaxRun")
}

func teeSelectRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	fp, sp, tp, fhs, shs, ths, err := extract3Operands("teeSelect", environment, input, runSpan)
	if err != nil {
		logger.Error("teeSelect", "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, sp.FheUintType), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if sp.FheUintType == tfhe.FheUint128 || sp.FheUintType == tfhe.FheUint160 {
		panic("TODO implement me")
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert th
	// result back to the FheUintType.
	var result uint64
	s := big.NewInt(0).SetBytes(sp.Value).Uint64()
	t := big.NewInt(0).SetBytes(tp.Value).Uint64()
	if fp.Value[0] == 1 {
		result = s
	} else {
		result = t
	}

	resultBz, err := marshalTfheType(result, sp.FheUintType)
	if err != nil {
		return nil, err
	}
	teePlaintext := tee.NewTeePlaintext(resultBz, sp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error("teeSelect", "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", "teeSelect"), "fhs", fhs.hash().Hex(), "shs", shs.hash().Hex(), "ths", ths.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}
