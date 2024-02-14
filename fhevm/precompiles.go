package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel"
)

func FheLibRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])

	fheLibMethod, found := GetFheLibMethod(signature)
	if !found {
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	// we remove function signature
	input = input[4:]
	return fheLibMethod.RequiredGas(environment, input)
}

func FheLibRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])

	fheLibMethod, found := GetFheLibMethod(signature)
	if !found {
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	// remove function signature
	input = input[4:]
	// trace function execution
	_, span := otel.Tracer("fhevm").Start(environment.OtelContext(), fheLibMethod.name)
	ret, err = fheLibMethod.Run(environment, caller, addr, input, readOnly)
	span.End()

	return
}
