package tfhe

/*
#include "tfhe_wrappers.h"
*/
import "C"

import (
	"fmt"
	"math/big"
	"os"
	"path"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Expanded TFHE ciphertext sizes by type, in bytes.
var ExpandedFheCiphertextSize map[FheUintType]uint

func GetExpandedFheCiphertextSize(t FheUintType) (size uint, found bool) {
	size, found = ExpandedFheCiphertextSize[t]
	return
}

// Compact TFHE ciphertext sizes by type, in bytes.
var compactFheCiphertextSize map[FheUintType]uint

func GetCompactFheCiphertextSize(t FheUintType) (size uint, found bool) {
	size, found = compactFheCiphertextSize[t]
	return
}

// server key: evaluation key
var sks unsafe.Pointer

// client key: secret key
var cks unsafe.Pointer

// public key
var pks unsafe.Pointer
var pksHash common.Hash

// Get public key hash
func GetPksHash() common.Hash {
	return pksHash
}

// Generate keys for the fhevm (sks, cks, psk)
func generateFhevmKeys() (unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) {
	var keys = C.generate_fhevm_keys()
	return keys.sks, keys.cks, keys.pks
}

func AllGlobalKeysPresent() bool {
	return sks != nil && cks != nil && pks != nil
}

func InitGlobalKeysWithNewKeys() {
	sks, cks, pks = generateFhevmKeys()
	initCiphertextSizes()
}

func initCiphertextSizes() {
	ExpandedFheCiphertextSize = make(map[FheUintType]uint)
	compactFheCiphertextSize = make(map[FheUintType]uint)

	ExpandedFheCiphertextSize[FheBool] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheBool).Serialize()))
	ExpandedFheCiphertextSize[FheUint4] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint4).Serialize()))
	ExpandedFheCiphertextSize[FheUint8] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint8).Serialize()))
	ExpandedFheCiphertextSize[FheUint16] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint16).Serialize()))
	ExpandedFheCiphertextSize[FheUint32] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint32).Serialize()))
	ExpandedFheCiphertextSize[FheUint64] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint64).Serialize()))
	ExpandedFheCiphertextSize[FheUint160] = uint(len(new(TfheCiphertext).TrivialEncrypt(*big.NewInt(0), FheUint160).Serialize()))

	compactFheCiphertextSize[FheBool] = uint(len(EncryptAndSerializeCompact(0, FheBool)))
	compactFheCiphertextSize[FheUint4] = uint(len(EncryptAndSerializeCompact(0, FheUint4)))
	compactFheCiphertextSize[FheUint8] = uint(len(EncryptAndSerializeCompact(0, FheUint8)))
	compactFheCiphertextSize[FheUint16] = uint(len(EncryptAndSerializeCompact(0, FheUint16)))
	compactFheCiphertextSize[FheUint32] = uint(len(EncryptAndSerializeCompact(0, FheUint32)))
	compactFheCiphertextSize[FheUint64] = uint(len(EncryptAndSerializeCompact(0, FheUint64)))
	compactFheCiphertextSize[FheUint160] = uint(len(EncryptAndSerializeCompact(0, FheUint160)))
}

func InitGlobalKeysFromFiles(keysDir string) error {
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		return fmt.Errorf("init_keys: global keys directory doesn't exist (FHEVM_GO_KEYS_DIR): %s", keysDir)
	}
	// read keys from files
	var sksPath = path.Join(keysDir, "sks")
	sksBytes, err := os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	var pksPath = path.Join(keysDir, "pks")
	pksBytes, err := os.ReadFile(pksPath)
	if err != nil {
		return err
	}
	// TODO: This is a temporary measure until we remove sync decrypt for FHE operations
	// ref: https://github.com/Inco-fhevm/fhevm-go/issues/13
	var cksPath = path.Join(keysDir, "cks")
	cksBytes, err := os.ReadFile(cksPath)
	if err != nil {
		return err
	}

	sks = C.deserialize_server_key(toDynamicBufferView(sksBytes))

	pksHash = crypto.Keccak256Hash(pksBytes)
	pks = C.deserialize_compact_public_key(toDynamicBufferView(pksBytes))

	cks = C.deserialize_client_key(toDynamicBufferView(cksBytes))

	initCiphertextSizes()

	fmt.Println("INFO: global keys loaded from: " + keysDir)

	return nil
}

// initialize keys automatically only if FHEVM_GO_KEYS_DIR is set
func init() {
	var keysDirPath, present = os.LookupEnv("FHEVM_GO_KEYS_DIR")
	if present {
		err := InitGlobalKeysFromFiles(keysDirPath)
		if err != nil {
			panic(err)
		}
		fmt.Println("INFO: global keys are initialized automatically using FHEVM_GO_KEYS_DIR env variable")
	} else {
		fmt.Println("INFO: global keys aren't initialized automatically (FHEVM_GO_KEYS_DIR env variable not set)")
	}
}
