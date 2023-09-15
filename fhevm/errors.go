package fhevm

import (
	"errors"
)

// List of EVM execution errors needed by the fhEVM
var (
	ErrWriteProtection = errors.New("write protection")
)
