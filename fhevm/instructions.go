package fhevm

import (
	"bytes"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/zama-ai/fhevm/crypto"
)

// A list of slots that we consider reserved in protected storage.
// Namely, we won't treat them as ciphertext metadata and we won't garbage collect them.
// TODO: This list will be removed when we change the way we handle ciphertext handles and refcounts.
var reservedProtectedStorageSlots []common.Hash = make([]common.Hash, 0)

var zero = uint256.NewInt(0).Bytes32()

func newInt(buf []byte) *uint256.Int {
	i := uint256.NewInt(0)
	return i.SetBytes(buf)
}

// Ciphertext metadata is stored in protected storage, in a 32-byte slot.
// Currently, we only utilize 17 bytes from the slot.
type ciphertextMetadata struct {
	refCount    uint64
	length      uint64
	fheUintType fheUintType
}

func (m ciphertextMetadata) serialize() [32]byte {
	u := uint256.NewInt(0)
	u[0] = m.refCount
	u[1] = m.length
	u[2] = uint64(m.fheUintType)
	return u.Bytes32()
}

func (m *ciphertextMetadata) deserialize(buf [32]byte) *ciphertextMetadata {
	u := uint256.NewInt(0)
	u.SetBytes(buf[:])
	m.refCount = u[0]
	m.length = u[1]
	m.fheUintType = fheUintType(u[2])
	return m
}

func newCiphertextMetadata(buf [32]byte) *ciphertextMetadata {
	m := ciphertextMetadata{}
	return m.deserialize(buf)
}

// If references are still left, reduce refCount by 1. Otherwise, zero out the metadata and the ciphertext slots.
func garbageCollectProtectedStorage(metadataKey common.Hash, protectedStorage common.Address, environment EVMEnvironment) {
	// If a reserved slot, do not try to garbage collect it.
	for _, slot := range reservedProtectedStorageSlots {
		if bytes.Equal(metadataKey.Bytes(), slot.Bytes()) {
			return
		}
	}
	existingMetadataHash := environment.GetState(protectedStorage, metadataKey)
	existingMetadataInt := newInt(existingMetadataHash.Bytes())
	if !existingMetadataInt.IsZero() {
		logger := environment.GetLogger()
		metadata := newCiphertextMetadata(existingMetadataInt.Bytes32())
		if metadata.refCount == 1 {
			if environment.IsCommitting() {
				logger.Info("opSstore garbage collecting ciphertext",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}

			// Zero the metadata key-value.
			environment.SetState(protectedStorage, metadataKey, zero)

			// Set the slot to the one after the metadata one.
			slot := newInt(metadataKey.Bytes())
			slot.AddUint64(slot, 1)

			// Zero the ciphertext slots.
			slotsToZero := metadata.length / 32
			if metadata.length > 0 && metadata.length < 32 {
				slotsToZero++
			}
			for i := uint64(0); i < slotsToZero; i++ {
				environment.SetState(protectedStorage, slot.Bytes32(), zero)
				slot.AddUint64(slot, 1)
			}
		} else if metadata.refCount > 1 {
			if environment.IsCommitting() {
				logger.Info("opSstore decrementing ciphertext refCount",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}
			metadata.refCount--
			environment.SetState(protectedStorage, existingMetadataHash, metadata.serialize())
		}
	}
}

func isVerifiedAtCurrentDepth(environment EVMEnvironment, ct *verifiedCiphertext) bool {
	return ct.verifiedDepths.has(environment.GetDepth())
}

// Returns a pointer to the ciphertext if the given hash points to a verified ciphertext.
// Else, it returns nil.
func getVerifiedCiphertextFromEVM(environment EVMEnvironment, ciphertextHash common.Hash) *verifiedCiphertext {
	ct, ok := environment.GetFhevmData().verifiedCiphertexts[ciphertextHash]
	if ok && isVerifiedAtCurrentDepth(environment, ct) {
		return ct
	}
	return nil
}

// If a verified ciphertext:
// * if the ciphertext does not exist in protected storage, persist it with a refCount = 1
// * if the ciphertexts exists in protected, bump its refCount by 1
func persistIfVerifiedCiphertext(val common.Hash, protectedStorage common.Address, environment EVMEnvironment) {
	verifiedCiphertext := getVerifiedCiphertextFromEVM(environment, val)
	if verifiedCiphertext == nil {
		return
	}
	logger := environment.GetLogger()
	// Try to read ciphertext metadata from protected storage.
	metadataInt := newInt(environment.GetState(protectedStorage, val).Bytes())
	metadata := ciphertextMetadata{}
	if metadataInt.IsZero() {
		// If no metadata, it means this ciphertext itself hasn't been persisted to protected storage yet. We do that as part of SSTORE.
		metadata.refCount = 1
		metadata.length = uint64(expandedFheCiphertextSize[verifiedCiphertext.ciphertext.fheUintType])
		metadata.fheUintType = verifiedCiphertext.ciphertext.fheUintType
		ciphertextSlot := newInt(val.Bytes())
		ciphertextSlot.AddUint64(ciphertextSlot, 1)
		if environment.IsCommitting() {
			logger.Info("opSstore persisting new ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(val.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"ciphertextSlot", hex.EncodeToString(ciphertextSlot.Bytes()))
		}
		ctPart32 := make([]byte, 32)
		partIdx := 0
		ctBytes := verifiedCiphertext.ciphertext.serialize()
		for i, b := range ctBytes {
			if i%32 == 0 && i != 0 {
				environment.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
				ciphertextSlot.AddUint64(ciphertextSlot, 1)
				ctPart32 = make([]byte, 32)
				partIdx = 0
			}
			ctPart32[partIdx] = b
			partIdx++
		}
		if len(ctPart32) != 0 {
			environment.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
		}
	} else {
		// If metadata exists, bump the refcount by 1.
		metadata = *newCiphertextMetadata(environment.GetState(protectedStorage, val))
		metadata.refCount++
		if environment.IsCommitting() {
			logger.Info("opSstore bumping refcount of existing ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(val.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"refCount", metadata.refCount)
		}
	}
	// Save the metadata in protected storage.
	environment.SetState(protectedStorage, val, metadata.serialize())
}

func OpSstore(pc *uint64, environment EVMEnvironment, scope ScopeContext) ([]byte, error) {
	if environment.IsReadOnly() {
		return nil, ErrWriteProtection
	}
	loc := scope.GetStack().Pop()
	newVal := scope.GetStack().Pop()
	newValBytes := newVal.Bytes()
	newValHash := common.BytesToHash(newValBytes)
	oldValHash := environment.GetState(scope.GetContract().Address(), common.Hash(loc.Bytes32()))
	protectedStorage := crypto.CreateProtectedStorageContractAddress(scope.GetContract().Address())
	// If the value is the same or if we are not going to commit, don't do anything to protected storage.
	if newValHash != oldValHash && environment.IsCommitting() {
		// Since the old value is no longer stored in actual contract storage, run garbage collection on protected storage.
		garbageCollectProtectedStorage(oldValHash, protectedStorage, environment)
		// If a verified ciphertext, persist to protected storage.
		persistIfVerifiedCiphertext(newValHash, protectedStorage, environment)
	}
	// Set the SSTORE's value in the actual contract.
	environment.SetState(scope.GetContract().Address(),
		loc.Bytes32(), newValHash)
	return nil, nil
}
