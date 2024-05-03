package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func teeAddRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a + b
	}, "teeAddRun")
}

func teeSubRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a - b
	}, "teeSubRun")
}

func teeMulRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a * b
	}, "teeMulRun")
}

func teeDivRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a / b
	}, "teeDivRun")
}

func teeRemRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a % b
	}, "teeRemRun")
}
