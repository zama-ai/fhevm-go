package fhevm

import (
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/crypto"
	"github.com/zama-ai/fhevm-go/tfhe"
	"go.opentelemetry.io/otel"
)

var zero = common.BytesToHash(uint256.NewInt(0).Bytes())

func newInt(buf []byte) *uint256.Int {
	i := uint256.NewInt(0)
	return i.SetBytes(buf)
}

func contains(haystack []byte, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}

func isVerifiedAtCurrentDepth(environment EVMEnvironment, ct *verifiedCiphertext) bool {
	return ct.verifiedDepths.has(environment.GetDepth())
}

// Returns a pointer to the ciphertext if the given hash points to a verified ciphertext.
// Else, it returns nil.
func getVerifiedCiphertextFromEVM(environment EVMEnvironment, ciphertextHash common.Hash) *verifiedCiphertext {
	ct, ok := environment.FhevmData().verifiedCiphertexts[ciphertextHash]
	if ok && isVerifiedAtCurrentDepth(environment, ct) {
		return ct
	}
	return nil
}

func verifyIfCiphertextHandle(handle common.Hash, env EVMEnvironment, contractAddress common.Address) error {
	ct, ok := env.FhevmData().verifiedCiphertexts[handle]
	if ok {
		// If already existing in memory, skip storage and import the same ciphertext at the current depth.
		//
		// Also works for gas estimation - we don't persist anything to protected storage during gas estimation.
		// However, ciphertexts remain in memory for the duration of the call, allowing for this lookup to find it.
		// Note that even if a ciphertext has an empty verification depth set, it still remains in memory.
		importCiphertextToEVM(env, ct.ciphertext)
		return nil
	}

	ciphertext := getCiphertextFromProtectedStoage(env, contractAddress, handle)
	if ciphertext != nil {
		ct := new(tfhe.TfheCiphertext)
		err := ct.Deserialize(ciphertext.bytes, ciphertext.metadata.fheUintType)
		if err != nil {
			msg := "opSload failed to deserialize a ciphertext"
			env.GetLogger().Error(msg, "err", err)
			return errors.New(msg)
		}
		importCiphertextToEVM(env, ct)
	}
	return nil
}

// This function is a modified copy from https://github.com/ethereum/go-ethereum
func OpSload(pc *uint64, env EVMEnvironment, scope ScopeContext) ([]byte, error) {
	if otelCtx := env.OtelContext(); otelCtx != nil {
		_, span := otel.Tracer("fhevm").Start(otelCtx, "OpSload")
		defer span.End()
	}
	loc := scope.GetStack().Peek()
	hash := common.Hash(loc.Bytes32())
	val := env.GetState(scope.GetContract().Address(), hash)
	if err := verifyIfCiphertextHandle(val, env, scope.GetContract().Address()); err != nil {
		return nil, err
	}
	loc.SetBytes(val.Bytes())
	return nil, nil
}

func OpSstore(pc *uint64, env EVMEnvironment, scope ScopeContext) ([]byte, error) {
	// This function is a modified copy from https://github.com/ethereum/go-ethereum
	if otelCtx := env.OtelContext(); otelCtx != nil {
		_, span := otel.Tracer("fhevm").Start(otelCtx, "OpSstore")
		defer span.End()
	}
	if env.IsReadOnly() {
		return nil, ErrWriteProtection
	}
	loc := scope.GetStack().Pop()
	locHash := common.BytesToHash(loc.Bytes())
	newVal := scope.GetStack().Pop()
	newValHash := common.BytesToHash(newVal.Bytes())
	oldValHash := env.GetState(scope.GetContract().Address(), common.Hash(loc.Bytes32()))
	// If the value is the same or if we are not going to commit, don't do anything to protected storage.
	if newValHash != oldValHash && env.IsCommitting() {
		protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(scope.GetContract().Address())

		// Define flag location as keccak256(keccak256(loc)) in protected storage. Used to mark the location as containing a handle.
		// Note: We apply the hash function twice to make sure a flag location in protected storage cannot clash with a ciphertext
		// metadata location that is keccak256(keccak256(ciphertext)). Since a location is 32 bytes, it cannot clash with a well-formed
		// ciphertext. Therefore, there needs to be a hash collistion for a clash to happen. If hash is applied only once, there could
		// be a collision, since malicous users could store at loc = keccak256(ciphertext), making the flag clash with metadata.
		flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash[:]).Bytes())

		// Since the old value is no longer stored in actual contract storage, run garbage collection on protected storage.
		garbageCollectProtectedStorage(flagHandleLocation, oldValHash, protectedStorage, env)

		// If a verified ciphertext, persist to protected storage.
		persistIfVerifiedCiphertext(flagHandleLocation, newValHash, protectedStorage, env)
	}
	// Set the SSTORE's value in the actual contract.
	env.SetState(scope.GetContract().Address(), loc.Bytes32(), newValHash)
	return nil, nil
}

// If there are ciphertext handles in the arguments to a call, delegate them to the callee.
// Return a map from ciphertext hash -> depthSet before delegation.
func DelegateCiphertextHandlesInArgs(env EVMEnvironment, args []byte) (verified map[common.Hash]*depthSet) {
	verified = make(map[common.Hash]*depthSet)
	for key, verifiedCiphertext := range env.FhevmData().verifiedCiphertexts {
		if contains(args, key.Bytes()) && isVerifiedAtCurrentDepth(env, verifiedCiphertext) {
			if env.IsCommitting() {
				env.GetLogger().Info("delegateCiphertextHandlesInArgs",
					"handle", verifiedCiphertext.ciphertext.GetHash().Hex(),
					"fromDepth", env.GetDepth(),
					"toDepth", env.GetDepth()+1)
			}
			verified[key] = verifiedCiphertext.verifiedDepths.clone()
			verifiedCiphertext.verifiedDepths.add(env.GetDepth() + 1)
		}
	}
	return
}

func RestoreVerifiedDepths(env EVMEnvironment, verified map[common.Hash]*depthSet) {
	for k, v := range verified {
		env.FhevmData().verifiedCiphertexts[k].verifiedDepths = v
	}
}

func delegateCiphertextHandlesToCaller(env EVMEnvironment, ret []byte) {
	for key, verifiedCiphertext := range env.FhevmData().verifiedCiphertexts {
		if contains(ret, key.Bytes()) && isVerifiedAtCurrentDepth(env, verifiedCiphertext) {
			if env.IsCommitting() {
				env.GetLogger().Info("opReturn making ciphertext available to caller",
					"handle", verifiedCiphertext.ciphertext.GetHash().Hex(),
					"fromDepth", env.GetDepth(),
					"toDepth", env.GetDepth()-1)
			}
			// If a handle is returned, automatically make it available to the caller.
			verifiedCiphertext.verifiedDepths.add(env.GetDepth() - 1)
		}
	}
}

func RemoveVerifiedCipherextsAtCurrentDepth(env EVMEnvironment) {
	for _, verifiedCiphertext := range env.FhevmData().verifiedCiphertexts {
		if env.IsCommitting() {
			env.GetLogger().Info("Run removing ciphertext from depth",
				"handle", verifiedCiphertext.ciphertext.GetHash().Hex(),
				"depth", env.GetDepth())
		}
		// Delete the current EVM depth from the set of verified depths.
		verifiedCiphertext.verifiedDepths.del(env.GetDepth())
	}
}

func OpReturn(pc *uint64, env EVMEnvironment, scope ScopeContext) []byte {
	// This function is a modified copy from https://github.com/ethereum/go-ethereum
	if otelCtx := env.OtelContext(); otelCtx != nil {
		_, span := otel.Tracer("fhevm").Start(otelCtx, "OpReturn")
		defer span.End()
	}
	offset, size := scope.GetStack().Pop(), scope.GetStack().Pop()
	ret := scope.GetMemory().GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	delegateCiphertextHandlesToCaller(env, ret)
	return ret
}

func OpSelfdestruct(pc *uint64, env EVMEnvironment, scope ScopeContext) (beneficiary uint256.Int, balance *big.Int) {
	// This function is a modified copy from https://github.com/ethereum/go-ethereum
	beneficiary = scope.GetStack().Pop()
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(scope.GetContract().Address())
	balance = env.GetBalance(scope.GetContract().Address())
	balance.Add(balance, env.GetBalance(protectedStorage))
	env.AddBalance(beneficiary.Bytes20(), balance)
	env.Suicide(scope.GetContract().Address())
	env.Suicide(protectedStorage)
	return
}
