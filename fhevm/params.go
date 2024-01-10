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
)

func DefaultFhevmParams() FhevmParams {
	return FhevmParams{
		GasCosts:                        DefaultGasCosts(),
		DisableDecryptionsInTransaction: false,
	}
}

type FhevmParams struct {
	GasCosts                        GasCosts
	DisableDecryptionsInTransaction bool
}

type GasCosts struct {
	FheCast             uint64
	FhePubKey           uint64
	FheAddSub           map[FheUintType]uint64
	FheDecrypt          map[FheUintType]uint64
	FheBitwiseOp        map[FheUintType]uint64
	FheMul              map[FheUintType]uint64
	FheDiv              map[FheUintType]uint64
	FheRem              map[FheUintType]uint64
	FheShift            map[FheUintType]uint64
	FheLe               map[FheUintType]uint64
	FheMinMax           map[FheUintType]uint64
	FheNegNot           map[FheUintType]uint64
	FheReencrypt        map[FheUintType]uint64
	FheTrivialEncrypt   map[FheUintType]uint64
	FheRand             map[FheUintType]uint64
	FheIfThenElse       map[FheUintType]uint64
	FheVerify           map[FheUintType]uint64
	FheOptRequire       map[FheUintType]uint64
	FheOptRequireBitAnd map[FheUintType]uint64
}

func DefaultGasCosts() GasCosts {
	return GasCosts{
		FheAddSub: map[FheUintType]uint64{
			FheUint8:  108000,
			FheUint16: 138000,
			FheUint32: 169000,
		},
		FheDecrypt: map[FheUintType]uint64{
			FheUint8:  500000,
			FheUint16: 500000,
			FheUint32: 500000,
		},
		FheBitwiseOp: map[FheUintType]uint64{
			FheUint8:  30000,
			FheUint16: 31000,
			FheUint32: 32000,
		},
		FheMul: map[FheUintType]uint64{
			FheUint8:  185000,
			FheUint16: 252000,
			FheUint32: 361000,
		},
		FheScalarMul: map[FheUintType]uint64{
			FheUint8:  128000,
			FheUint16: 132000,
			FheUint32: 168000,
		},
		FheScalarDiv: map[FheUintType]uint64{
			FheUint8:  200000,
			FheUint16: 400000,
			FheUint32: 800000,
		},
		FheScalarRem: map[FheUintType]uint64{
			FheUint8:  200000,
			FheUint16: 400000,
			FheUint32: 800000,
		},
		FheShift: map[FheUintType]uint64{
			FheUint8:  218000,
			FheUint16: 273000,
			FheUint32: 335000,
		},
		FheScalarShift: map[FheUintType]uint64{
			FheUint8:  135000,
			FheUint16: 161000,
			FheUint32: 188000,
		},
		FheLe: map[FheUintType]uint64{
			FheUint8:  50000,
			FheUint16: 53000,
			FheUint32: 56000,
		},
		FheMinMax: map[FheUintType]uint64{
			FheUint8:  215000,
			FheUint16: 272000,
			FheUint32: 332000,
		},
		FheScalarMinMax: map[FheUintType]uint64{
			FheUint8:  131000,
			FheUint16: 159000,
			FheUint32: 189000,
		},
		FheNegNot: map[FheUintType]uint64{
			FheUint8:  83000,
			FheUint16: 108000,
			FheUint32: 130000,
		},
		// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
		FheReencrypt: map[FheUintType]uint64{
			FheUint8:  1000,
			FheUint16: 1100,
			FheUint32: 1200,
		},
		// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
		FheVerify: map[FheUintType]uint64{
			FheUint8:  200,
			FheUint16: 300,
			FheUint32: 400,
		},
		FheTrivialEncrypt: map[FheUintType]uint64{
			FheUint8:  100,
			FheUint16: 200,
			FheUint32: 300,
		},
		// TODO: These will change once we have an FHE-based random generaration.
		FheRand: map[FheUintType]uint64{
			FheUint8:  EvmNetSstoreInitGas + 100000,
			FheUint16: EvmNetSstoreInitGas + 200000,
			FheUint32: EvmNetSstoreInitGas + 400000,
		},
		FheIfThenElse: map[FheUintType]uint64{
			FheUint8:  55000,
			FheUint16: 60000,
			FheUint32: 65000,
		},
		// TODO: As of now, only support FheUint8. All optimistic require predicates are
		// downcast to FheUint8 at the solidity level. Eventually move to ebool.
		// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
		// For every subsequent optimistic require, we need to bitand it with the current require value - that
		// works, because we assume requires have a value of 0 or 1.
		FheOptRequire: map[FheUintType]uint64{
			FheUint8:  170000,
			FheUint16: 180000,
			FheUint32: 190000,
		},
		FheOptRequireBitAnd: map[FheUintType]uint64{
			FheUint8:  20000,
			FheUint16: 20000,
			FheUint32: 20000,
		},
	}
}

var TxDataFractionalGasFactor uint64 = 4

func TxDataFractionalGas(originalGas uint64) (fractionalGas uint64) {
	return originalGas / TxDataFractionalGasFactor
}
