package fhevm

import (
	"errors"
)

// List of EVM execution errors needed by the fhEVM.
// TODO: initialize errors from erros passed by users. That would make fhevm-go errors match the EVM environment's errors.
var (
	ErrExecutionReverted = errors.New("execution reverted")
)
