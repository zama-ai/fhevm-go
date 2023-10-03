package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type EVMEnvironment interface {
	// StateDB related functions
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	// EVM call stack depth
	GetDepth() int

	// EVM Logger
	GetLogger() Logger

	// TODO: clarify meaning of the following
	IsCommitting() bool
	IsEthCall() bool
	IsReadOnly() bool

	GetFhevmData() *FhevmData
}

type FhevmData struct {
	// A map from a ciphertext hash to itself and stack depth at which it is verified
	verifiedCiphertexts map[common.Hash]*verifiedCiphertext

	// All optimistic requires encountered up to that point in the txn execution
	optimisticRequires []*tfheCiphertext

	nextCiphertextHashOnGasEst uint256.Int
}
