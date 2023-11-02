// BSD 3-Clause Clear License

// Copyright © 2023 ZAMA.
// All rights reserved.

// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package fhevm

// This file contains default gas costs of fhEVM-related operations.
// Users can change the values based on specific requirements in their blockchain.

// Base gas costs of existing EVM operations. Used for setting gas costs relative to them.
// These constants are used just for readability.
const EvmNetSstoreInitGas uint64 = 20000
const ColdSloadCostEIP2929 uint64 = 2100

var (
	// FHE operation costs depend on tfhe-rs performance and hardware acceleration. These values will most certainly change.
	FheUint8AddSubGas  uint64 = 83000
	FheUint16AddSubGas uint64 = 108000
	FheUint32AddSubGas uint64 = 130000
	FheUint8MulGas     uint64 = 150000
	FheUint16MulGas    uint64 = 200000
	FheUint32MulGas    uint64 = 270000
	// Div and Rem currently only support a plaintext divisor and below gas costs reflect that case only.
	FheUint8DivGas      uint64 = 200000
	FheUint16DivGas     uint64 = 250000
	FheUint32DivGas     uint64 = 350000
	FheUint8RemGas      uint64 = 200000
	FheUint16RemGas     uint64 = 250000
	FheUint32RemGas     uint64 = 350000
	FheUint8BitwiseGas  uint64 = 20000
	FheUint16BitwiseGas uint64 = 21000
	FheUint32BitwiseGas uint64 = 22000
	FheUint8ShiftGas    uint64 = 105000
	FheUint16ShiftGas   uint64 = 128000
	FheUint32ShiftGas   uint64 = 160000
	FheUint8LeGas       uint64 = 61000
	FheUint16LeGas      uint64 = 83000
	FheUint32LeGas      uint64 = 109000
	FheUint8MinMaxGas   uint64 = 108000
	FheUint16MinMaxGas  uint64 = 134000
	FheUint32MinMaxGas  uint64 = 150000
	FheUint8NegNotGas   uint64 = 83000
	FheUint16NegNotGas  uint64 = 108000
	FheUint32NegNotGas  uint64 = 130000

	// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
	FheUint8ReencryptGas  uint64 = 320000
	FheUint16ReencryptGas uint64 = 320400
	FheUint32ReencryptGas uint64 = 320800
	FheUint8DecryptGas    uint64 = 320000
	FheUint16DecryptGas   uint64 = 320400
	FheUint32DecryptGas   uint64 = 320800

	// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
	FheUint8VerifyGas  uint64 = 200
	FheUint16VerifyGas uint64 = 300
	FheUint32VerifyGas uint64 = 400

	// TODO: Cost will depend on the complexity of doing decryption by the oracle.
	FheUint8RequireGas  uint64 = 320000
	FheUint16RequireGas uint64 = 320400
	FheUint32RequireGas uint64 = 320800

	// TODO: As of now, only support FheUint8. All optimistic require predicates are
	// downcast to FheUint8 at the solidity level. Eventually move to ebool.
	// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
	// For every subsequent optimistic require, we need to bitand it with the current require value - that
	// works, because we assume requires have a value of 0 or 1.
	FheUint8OptimisticRequireGas       uint64 = FheUint8RequireGas
	FheUint8OptimisticRequireBitandGas uint64 = FheUint8BitwiseGas

	// TODO: These will change once we have an FHE-based random generaration.
	FheUint8RandGas  uint64 = EvmNetSstoreInitGas + 1000
	FheUint16RandGas uint64 = FheUint8RandGas + 1000
	FheUint32RandGas uint64 = FheUint16RandGas + 1000

	// TODO: The values here are chosen somewhat arbitrarily (at least the 8 bit ones). Also, we don't
	// take into account whether a ciphertext existed (either "current" or "original") for the given handle.
	// Finally, costs are likely to change in the future.
	FheUint8ProtectedStorageSstoreGas  uint64 = EvmNetSstoreInitGas + 2000
	FheUint16ProtectedStorageSstoreGas uint64 = FheUint8ProtectedStorageSstoreGas * 2
	FheUint32ProtectedStorageSstoreGas uint64 = FheUint16ProtectedStorageSstoreGas * 2

	// TODO: We don't take whether the slot is cold or warm into consideration.
	FheUint8ProtectedStorageSloadGas  uint64 = ColdSloadCostEIP2929 + 200
	FheUint16ProtectedStorageSloadGas uint64 = FheUint8ProtectedStorageSloadGas * 2
	FheUint32ProtectedStorageSloadGas uint64 = FheUint16ProtectedStorageSloadGas * 2

	FheCastGas uint64 = 100

	FhePubKeyGas uint64 = 2

	FheUint8TrivialEncryptGas  uint64 = 100
	FheUint16TrivialEncryptGas uint64 = 200
	FheUint32TrivialEncryptGas uint64 = 400
)
