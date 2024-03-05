package fhevm

import (
	"bytes"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/fhevm/crypto"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

// An arbitrary constant value to flag locations in protected storage.
var flag = common.HexToHash("0xa145ffde0100a145ffde0100a145ffde0100a145ffde0100a145ffde0100fab3")

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// Ciphertext metadata is stored in protected storage, in a 32-byte slot.
// Currently, we only utilize 17 bytes from the slot.
type ciphertextMetadata struct {
	refCount    uint64
	length      uint64
	fheUintType tfhe.FheUintType
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
	m.fheUintType = tfhe.FheUintType(u[2])
	return m
}

func newCiphertextMetadata(buf [32]byte) *ciphertextMetadata {
	m := ciphertextMetadata{}
	return m.deserialize(buf)
}

type ciphertextData struct {
	metadata *ciphertextMetadata
	bytes    []byte
}

func getCiphertextMetadataKey(handle common.Hash) common.Hash {
	return crypto.Keccak256Hash(handle.Bytes())
}

// Returns the ciphertext metadata for the given handle or nil if it doesn't point to a ciphertext.
func getCiphertextMetadataFromProtectedStorage(env EVMEnvironment, contractAddress common.Address, handle common.Hash) *ciphertextMetadata {
	metadataKey := getCiphertextMetadataKey(handle)
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(contractAddress)
	metadataInt := newInt(env.GetState(protectedStorage, metadataKey).Bytes())
	if metadataInt.IsZero() {
		return nil
	}
	return newCiphertextMetadata(metadataInt.Bytes32())
}

// Returns the ciphertext data for the given handle or nil if it doesn't point to a ciphertext.
func getCiphertextFromProtectedStoage(env EVMEnvironment, contractAddress common.Address, handle common.Hash) *ciphertextData {
	metadataKey := getCiphertextMetadataKey(handle)
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(contractAddress)
	metadataInt := newInt(env.GetState(protectedStorage, metadataKey).Bytes())
	if metadataInt.IsZero() {
		return nil
	}
	metadata := newCiphertextMetadata(metadataInt.Bytes32())
	ctBytes := make([]byte, 0)
	left := metadata.length
	protectedSlotIdx := newInt(metadataKey.Bytes())
	protectedSlotIdx.AddUint64(protectedSlotIdx, 1)
	for {
		if left == 0 {
			break
		}
		bytes := env.GetState(protectedStorage, protectedSlotIdx.Bytes32())
		toAppend := minUint64(uint64(len(bytes)), left)
		left -= toAppend
		ctBytes = append(ctBytes, bytes[0:toAppend]...)
		protectedSlotIdx.AddUint64(protectedSlotIdx, 1)
	}
	return &ciphertextData{metadata: metadata, bytes: ctBytes}
}

// If a verified ciphertext:
// * if the ciphertext does not exist in protected storage, persist it with a refCount = 1
// * if the ciphertexts exists in protected, bump its refCount by 1
func persistIfVerifiedCiphertext(flagHandleLocation common.Hash, handle common.Hash, protectedStorage common.Address, env EVMEnvironment) {
	verifiedCiphertext := getVerifiedCiphertextFromEVM(env, handle)
	if verifiedCiphertext == nil {
		return
	}
	logger := env.GetLogger()

	// Try to read ciphertext metadata from protected storage.
	metadataKey := crypto.Keccak256Hash(handle.Bytes())
	metadataInt := newInt(env.GetState(protectedStorage, metadataKey).Bytes())
	metadata := ciphertextMetadata{}

	// Set flag in protected storage to mark the location as containing a handle.
	env.SetState(protectedStorage, flagHandleLocation, flag)

	if metadataInt.IsZero() {
		// If no metadata, it means this ciphertext itself hasn't been persisted to protected storage yet. We do that as part of SSTORE.
		metadata.refCount = 1
		metadata.length = uint64(tfhe.ExpandedFheCiphertextSize[verifiedCiphertext.ciphertext.FheUintType])
		metadata.fheUintType = verifiedCiphertext.ciphertext.FheUintType
		ciphertextSlot := newInt(metadataKey.Bytes())
		ciphertextSlot.AddUint64(ciphertextSlot, 1)
		if env.IsCommitting() {
			logger.Info("opSstore persisting new ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(handle.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"ciphertextSlot", hex.EncodeToString(ciphertextSlot.Bytes()))
		}
		ctPart32 := make([]byte, 32)
		partIdx := 0
		ctBytes := verifiedCiphertext.ciphertext.Serialize()
		for i, b := range ctBytes {
			if i%32 == 0 && i != 0 {
				env.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
				ciphertextSlot.AddUint64(ciphertextSlot, 1)
				ctPart32 = make([]byte, 32)
				partIdx = 0
			}
			ctPart32[partIdx] = b
			partIdx++
		}
		if len(ctPart32) != 0 {
			env.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
		}
	} else {
		// If metadata exists, bump the refcount by 1.
		metadata = *newCiphertextMetadata(env.GetState(protectedStorage, metadataKey))
		metadata.refCount++
		if env.IsCommitting() {
			logger.Info("opSstore bumping refcount of existing ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(handle.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"refCount", metadata.refCount)
		}
	}
	// Save the metadata in protected storage.
	env.SetState(protectedStorage, metadataKey, metadata.serialize())
}

// If references are still left, reduce refCount by 1. Otherwise, zero out the metadata and the ciphertext slots.
func garbageCollectProtectedStorage(flagHandleLocation common.Hash, handle common.Hash, protectedStorage common.Address, env EVMEnvironment) {
	// The location of ciphertext metadata is at Keccak256(handle). Doing so avoids attacks from users trying to garbage
	// collect arbitrary locations in protected storage. Hashing the handle makes it hard to find a preimage such that
	// it ends up in arbitrary non-zero places in protected stroage.
	metadataKey := crypto.Keccak256Hash(handle.Bytes())

	existingMetadataHash := env.GetState(protectedStorage, metadataKey)
	existingMetadataInt := newInt(existingMetadataHash.Bytes())
	if !existingMetadataInt.IsZero() {
		logger := env.GetLogger()

		// If no flag in protected storage for the location, ignore garbage collection.
		// Else, set the value at the location to zero.
		foundFlag := env.GetState(protectedStorage, flagHandleLocation)
		if !bytes.Equal(foundFlag.Bytes(), flag.Bytes()) {
			logger.Error("opSstore location flag not found for a ciphertext handle, ignoring garbage collection",
				"expectedFlag", hex.EncodeToString(flag[:]),
				"foundFlag", hex.EncodeToString(foundFlag[:]),
				"flagHandleLocation", hex.EncodeToString(flagHandleLocation[:]))
			return
		} else {
			env.SetState(protectedStorage, flagHandleLocation, zero)
		}

		metadata := newCiphertextMetadata(existingMetadataInt.Bytes32())
		if metadata.refCount == 1 {
			if env.IsCommitting() {
				logger.Info("opSstore garbage collecting ciphertext",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}

			// Zero the metadata key-value.
			env.SetState(protectedStorage, metadataKey, zero)

			// Set the slot to the one after the metadata one.
			slot := newInt(metadataKey.Bytes())
			slot.AddUint64(slot, 1)

			// Zero the ciphertext slots.
			slotsToZero := metadata.length / 32
			if metadata.length > 0 && metadata.length < 32 {
				slotsToZero++
			}
			for i := uint64(0); i < slotsToZero; i++ {
				env.SetState(protectedStorage, slot.Bytes32(), zero)
				slot.AddUint64(slot, 1)
			}
		} else if metadata.refCount > 1 {
			if env.IsCommitting() {
				logger.Info("opSstore decrementing ciphertext refCount",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}
			metadata.refCount--
			env.SetState(protectedStorage, existingMetadataHash, metadata.serialize())
		}
	}
}
