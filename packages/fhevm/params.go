package fhevm

import "github.com/zama-ai/fhevm-go/tfhe"

// This file contains default gas costs of fhEVM-related operations.
// Users can change the values based on specific requirements in their blockchain.

// Base gas costs of existing EVM operations. Used for setting gas costs relative to them.
// These constants are used just for readability.
const EvmNetSstoreInitGas uint64 = 20000
const AdjustFHEGas uint64 = 10000
const ColdSloadCostEIP2929 uint64 = 2100

const GetNonExistentCiphertextGas uint64 = 1000

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
	FheAddSub           map[tfhe.FheUintType]uint64
	FheDecrypt          map[tfhe.FheUintType]uint64
	FheBitwiseOp        map[tfhe.FheUintType]uint64
	FheMul              map[tfhe.FheUintType]uint64
	FheScalarMul        map[tfhe.FheUintType]uint64
	FheScalarDiv        map[tfhe.FheUintType]uint64
	FheScalarRem        map[tfhe.FheUintType]uint64
	FheShift            map[tfhe.FheUintType]uint64
	FheScalarShift      map[tfhe.FheUintType]uint64
	FheEq               map[tfhe.FheUintType]uint64
	FheLe               map[tfhe.FheUintType]uint64
	FheMinMax           map[tfhe.FheUintType]uint64
	FheScalarMinMax     map[tfhe.FheUintType]uint64
	FheNot              map[tfhe.FheUintType]uint64
	FheNeg              map[tfhe.FheUintType]uint64
	FheReencrypt        map[tfhe.FheUintType]uint64
	FheTrivialEncrypt   map[tfhe.FheUintType]uint64
	FheRand             map[tfhe.FheUintType]uint64
	FheIfThenElse       map[tfhe.FheUintType]uint64
	FheVerify           map[tfhe.FheUintType]uint64
	FheOptRequire       map[tfhe.FheUintType]uint64
	FheOptRequireBitAnd map[tfhe.FheUintType]uint64
	FheGetCiphertext    map[tfhe.FheUintType]uint64
}

func DefaultGasCosts() GasCosts {
	return GasCosts{
		FheAddSub: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  55000 + AdjustFHEGas,
			tfhe.FheUint8:  84000 + AdjustFHEGas,
			tfhe.FheUint16: 123000 + AdjustFHEGas,
			tfhe.FheUint32: 152000 + AdjustFHEGas,
			tfhe.FheUint64: 178000 + AdjustFHEGas,
		},
		FheDecrypt: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  500000,
			tfhe.FheUint8:  500000,
			tfhe.FheUint16: 500000,
			tfhe.FheUint32: 500000,
			tfhe.FheUint64: 500000,
		},
		FheBitwiseOp: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:  16000 + AdjustFHEGas,
			tfhe.FheUint4:  22000 + AdjustFHEGas,
			tfhe.FheUint8:  24000 + AdjustFHEGas,
			tfhe.FheUint16: 24000 + AdjustFHEGas,
			tfhe.FheUint32: 25000 + AdjustFHEGas,
			tfhe.FheUint64: 28000 + AdjustFHEGas,
		},
		FheMul: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  140000 + AdjustFHEGas,
			tfhe.FheUint8:  187000 + AdjustFHEGas,
			tfhe.FheUint16: 252000 + AdjustFHEGas,
			tfhe.FheUint32: 349000 + AdjustFHEGas,
			tfhe.FheUint64: 631000 + AdjustFHEGas,
		},
		FheScalarMul: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  78000 + AdjustFHEGas,
			tfhe.FheUint8:  149000 + AdjustFHEGas,
			tfhe.FheUint16: 198000 + AdjustFHEGas,
			tfhe.FheUint32: 254000 + AdjustFHEGas,
			tfhe.FheUint64: 346000 + AdjustFHEGas,
		},
		FheScalarDiv: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  129000 + AdjustFHEGas,
			tfhe.FheUint8:  228000 + AdjustFHEGas,
			tfhe.FheUint16: 304000 + AdjustFHEGas,
			tfhe.FheUint32: 388000 + AdjustFHEGas,
			tfhe.FheUint64: 574000 + AdjustFHEGas,
		},
		FheScalarRem: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  276000 + AdjustFHEGas,
			tfhe.FheUint8:  450000 + AdjustFHEGas,
			tfhe.FheUint16: 612000 + AdjustFHEGas,
			tfhe.FheUint32: 795000 + AdjustFHEGas,
			tfhe.FheUint64: 1095000 + AdjustFHEGas,
		},
		FheShift: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  106000 + AdjustFHEGas,
			tfhe.FheUint8:  123000 + AdjustFHEGas,
			tfhe.FheUint16: 143000 + AdjustFHEGas,
			tfhe.FheUint32: 173000 + AdjustFHEGas,
			tfhe.FheUint64: 217000 + AdjustFHEGas,
		},
		FheScalarShift: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  25000 + AdjustFHEGas,
			tfhe.FheUint8:  25000 + AdjustFHEGas,
			tfhe.FheUint16: 25000 + AdjustFHEGas,
			tfhe.FheUint32: 25000 + AdjustFHEGas,
			tfhe.FheUint64: 28000 + AdjustFHEGas,
		},
		FheEq: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  41000 + AdjustFHEGas,
			tfhe.FheUint8:  43000 + AdjustFHEGas,
			tfhe.FheUint16: 44000 + AdjustFHEGas,
			tfhe.FheUint32: 72000 + AdjustFHEGas,
			tfhe.FheUint64: 76000 + AdjustFHEGas,
		},
		FheLe: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  60000 + AdjustFHEGas,
			tfhe.FheUint8:  72000 + AdjustFHEGas,
			tfhe.FheUint16: 95000 + AdjustFHEGas,
			tfhe.FheUint32: 118000 + AdjustFHEGas,
			tfhe.FheUint64: 146000 + AdjustFHEGas,
		},
		FheMinMax: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  106000 + AdjustFHEGas,
			tfhe.FheUint8:  118000 + AdjustFHEGas,
			tfhe.FheUint16: 143000 + AdjustFHEGas,
			tfhe.FheUint32: 173000 + AdjustFHEGas,
			tfhe.FheUint64: 200000 + AdjustFHEGas,
		},
		FheScalarMinMax: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  111000 + AdjustFHEGas,
			tfhe.FheUint8:  114000 + AdjustFHEGas,
			tfhe.FheUint16: 140000 + AdjustFHEGas,
			tfhe.FheUint32: 154000 + AdjustFHEGas,
			tfhe.FheUint64: 182000 + AdjustFHEGas,
		},
		FheNot: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  23000 + AdjustFHEGas,
			tfhe.FheUint8:  24000 + AdjustFHEGas,
			tfhe.FheUint16: 25000 + AdjustFHEGas,
			tfhe.FheUint32: 26000 + AdjustFHEGas,
			tfhe.FheUint64: 27000 + AdjustFHEGas,
		},
		FheNeg: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  50000 + AdjustFHEGas,
			tfhe.FheUint8:  85000 + AdjustFHEGas,
			tfhe.FheUint16: 121000 + AdjustFHEGas,
			tfhe.FheUint32: 150000 + AdjustFHEGas,
			tfhe.FheUint64: 189000 + AdjustFHEGas,
		},
		// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
		FheReencrypt: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:  1000,
			tfhe.FheUint4:  1000,
			tfhe.FheUint8:  1000,
			tfhe.FheUint16: 1100,
			tfhe.FheUint32: 1200,
		},
		// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
		FheVerify: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:  200,
			tfhe.FheUint4:  200,
			tfhe.FheUint8:  200,
			tfhe.FheUint16: 300,
			tfhe.FheUint32: 400,
			tfhe.FheUint64: 800,
		},
		FheTrivialEncrypt: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:  100,
			tfhe.FheUint4:  100,
			tfhe.FheUint8:  100,
			tfhe.FheUint16: 200,
			tfhe.FheUint32: 300,
			tfhe.FheUint64: 600,
		},
		// TODO: These will change once we have an FHE-based random generaration.
		FheRand: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  EvmNetSstoreInitGas + 100000,
			tfhe.FheUint8:  EvmNetSstoreInitGas + 100000,
			tfhe.FheUint16: EvmNetSstoreInitGas + 100000,
			tfhe.FheUint32: EvmNetSstoreInitGas + 100000,
			tfhe.FheUint64: EvmNetSstoreInitGas + 100000,
		},
		FheIfThenElse: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  35000 + AdjustFHEGas,
			tfhe.FheUint8:  37000 + AdjustFHEGas,
			tfhe.FheUint16: 37000 + AdjustFHEGas,
			tfhe.FheUint32: 40000 + AdjustFHEGas,
			tfhe.FheUint64: 43000 + AdjustFHEGas,
		},
		// TODO: As of now, only support FheUint8. All optimistic require predicates are
		// downcast to FheUint8 at the solidity level. Eventually move to ebool.
		// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
		// For every subsequent optimistic require, we need to bitand it with the current require value - that
		// works, because we assume requires have a value of 0 or 1.
		FheOptRequire: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  170000,
			tfhe.FheUint8:  170000,
			tfhe.FheUint16: 180000,
			tfhe.FheUint32: 190000,
		},
		FheOptRequireBitAnd: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  20000,
			tfhe.FheUint8:  20000,
			tfhe.FheUint16: 20000,
			tfhe.FheUint32: 20000,
		},
		FheGetCiphertext: map[tfhe.FheUintType]uint64{
			tfhe.FheUint8:  12000,
			tfhe.FheUint16: 14000,
			tfhe.FheUint32: 18000,
			tfhe.FheUint64: 28000,
		},
	}
}

var TxDataFractionalGasFactor uint64 = 4

func TxDataFractionalGas(originalGas uint64) (fractionalGas uint64) {
	return originalGas / TxDataFractionalGasFactor
}
