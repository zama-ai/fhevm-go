package fhevm

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
	FheAddSub           map[FheUintType]uint64
	FheDecrypt          map[FheUintType]uint64
	FheBitwiseOp        map[FheUintType]uint64
	FheMul              map[FheUintType]uint64
	FheScalarMul        map[FheUintType]uint64
	FheScalarDiv        map[FheUintType]uint64
	FheScalarRem        map[FheUintType]uint64
	FheShift            map[FheUintType]uint64
	FheScalarShift      map[FheUintType]uint64
	FheLe               map[FheUintType]uint64
	FheMinMax           map[FheUintType]uint64
	FheScalarMinMax     map[FheUintType]uint64
	FheNot              map[FheUintType]uint64
	FheNeg              map[FheUintType]uint64
	FheReencrypt        map[FheUintType]uint64
	FheTrivialEncrypt   map[FheUintType]uint64
	FheRand             map[FheUintType]uint64
	FheIfThenElse       map[FheUintType]uint64
	FheVerify           map[FheUintType]uint64
	FheOptRequire       map[FheUintType]uint64
	FheOptRequireBitAnd map[FheUintType]uint64
	FheGetCiphertext    map[FheUintType]uint64
}

func DefaultGasCosts() GasCosts {
	return GasCosts{
		FheAddSub: map[FheUintType]uint64{
			FheUint4:  60000 + AdjustFHEGas,
			FheUint8:  84000 + AdjustFHEGas,
			FheUint16: 123000 + AdjustFHEGas,
			FheUint32: 152000 + AdjustFHEGas,
			FheUint64: 178000 + AdjustFHEGas,
		},
		FheDecrypt: map[FheUintType]uint64{
			FheUint4:  500000,
			FheUint8:  500000,
			FheUint16: 500000,
			FheUint32: 500000,
			FheUint64: 500000,
		},
		FheBitwiseOp: map[FheUintType]uint64{
			FheBool:  16000 + AdjustFHEGas,
			FheUint4:  23000 + AdjustFHEGas,
			FheUint8:  24000 + AdjustFHEGas,
			FheUint16: 24000 + AdjustFHEGas,
			FheUint32: 25000 + AdjustFHEGas,
			FheUint64: 28000 + AdjustFHEGas,
		},
		FheMul: map[FheUintType]uint64{
			FheUint4:  140000 + AdjustFHEGas,
			FheUint8:  187000 + AdjustFHEGas,
			FheUint16: 252000 + AdjustFHEGas,
			FheUint32: 349000 + AdjustFHEGas,
			FheUint64: 631000 + AdjustFHEGas,
		},
		FheScalarMul: map[FheUintType]uint64{
			FheUint4:  110000 + AdjustFHEGas,
			FheUint8:  149000 + AdjustFHEGas,
			FheUint16: 198000 + AdjustFHEGas,
			FheUint32: 254000 + AdjustFHEGas,
			FheUint64: 346000 + AdjustFHEGas,
		},
		FheScalarDiv: map[FheUintType]uint64{
			FheUint4:  120000 + AdjustFHEGas,
			FheUint8:  228000 + AdjustFHEGas,
			FheUint16: 304000 + AdjustFHEGas,
			FheUint32: 388000 + AdjustFHEGas,
			FheUint64: 574000 + AdjustFHEGas,
		},
		FheScalarRem: map[FheUintType]uint64{
			FheUint4:  250000 + AdjustFHEGas,
			FheUint8:  450000 + AdjustFHEGas,
			FheUint16: 612000 + AdjustFHEGas,
			FheUint32: 795000 + AdjustFHEGas,
			FheUint64: 1095000 + AdjustFHEGas,
		},
		FheShift: map[FheUintType]uint64{
			FheUint4:  110000 + AdjustFHEGas,
			FheUint8:  123000 + AdjustFHEGas,
			FheUint16: 143000 + AdjustFHEGas,
			FheUint32: 173000 + AdjustFHEGas,
			FheUint64: 217000 + AdjustFHEGas,
		},
		FheScalarShift: map[FheUintType]uint64{
			FheUint4:  25000 + AdjustFHEGas,
			FheUint8:  25000 + AdjustFHEGas,
			FheUint16: 25000 + AdjustFHEGas,
			FheUint32: 25000 + AdjustFHEGas,
			FheUint64: 28000 + AdjustFHEGas,
		},
		FheLe: map[FheUintType]uint64{
			FheUint4:  46000 + AdjustFHEGas,
			FheUint8:  46000 + AdjustFHEGas,
			FheUint16: 46000 + AdjustFHEGas,
			FheUint32: 72000 + AdjustFHEGas,
			FheUint64: 76000 + AdjustFHEGas,
		},
		FheMinMax: map[FheUintType]uint64{
			FheUint4:  50000 + AdjustFHEGas,
			FheUint8:  94000 + AdjustFHEGas,
			FheUint16: 120000 + AdjustFHEGas,
			FheUint32: 148000 + AdjustFHEGas,
			FheUint64: 189000 + AdjustFHEGas,
		},
		FheScalarMinMax: map[FheUintType]uint64{
			FheUint4:  80000 + AdjustFHEGas,
			FheUint8:  114000 + AdjustFHEGas,
			FheUint16: 140000 + AdjustFHEGas,
			FheUint32: 154000 + AdjustFHEGas,
			FheUint64: 182000 + AdjustFHEGas,
		},
		FheNot: map[FheUintType]uint64{
			FheUint4:  25000 + AdjustFHEGas,
			FheUint8:  25000 + AdjustFHEGas,
			FheUint16: 25000 + AdjustFHEGas,
			FheUint32: 26000 + AdjustFHEGas,
			FheUint64: 27000 + AdjustFHEGas,
		},
		FheNeg: map[FheUintType]uint64{
			FheUint4:  50000 + AdjustFHEGas,
			FheUint8:  79000 + AdjustFHEGas,
			FheUint16: 114000 + AdjustFHEGas,
			FheUint32: 150000 + AdjustFHEGas,
			FheUint64: 189000 + AdjustFHEGas,
		},
		// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
		FheReencrypt: map[FheUintType]uint64{
			FheBool:  1000,
			FheUint4:  1000,
			FheUint8:  1000,
			FheUint16: 1100,
			FheUint32: 1200,
		},
		// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
		FheVerify: map[FheUintType]uint64{
			FheBool:  200,
			FheUint4:  200,
			FheUint8:  200,
			FheUint16: 300,
			FheUint32: 400,
			FheUint64: 800,
		},
		FheTrivialEncrypt: map[FheUintType]uint64{
			FheBool:  100,
			FheUint4:  100,
			FheUint8:  100,
			FheUint16: 200,
			FheUint32: 300,
			FheUint64: 600,
		},
		// TODO: These will change once we have an FHE-based random generaration.
		FheRand: map[FheUintType]uint64{
			FheUint4:  EvmNetSstoreInitGas + 100000,
			FheUint8:  EvmNetSstoreInitGas + 100000,
			FheUint16: EvmNetSstoreInitGas + 100000,
			FheUint32: EvmNetSstoreInitGas + 100000,
			FheUint64: EvmNetSstoreInitGas + 100000,
		},
		FheIfThenElse: map[FheUintType]uint64{
			FheUint4:  37000 + AdjustFHEGas,
			FheUint8:  37000 + AdjustFHEGas,
			FheUint16: 37000 + AdjustFHEGas,
			FheUint32: 40000 + AdjustFHEGas,
			FheUint64: 43000 + AdjustFHEGas,
		},
		// TODO: As of now, only support FheUint8. All optimistic require predicates are
		// downcast to FheUint8 at the solidity level. Eventually move to ebool.
		// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
		// For every subsequent optimistic require, we need to bitand it with the current require value - that
		// works, because we assume requires have a value of 0 or 1.
		FheOptRequire: map[FheUintType]uint64{
			FheUint4:  170000,
			FheUint8:  170000,
			FheUint16: 180000,
			FheUint32: 190000,
		},
		FheOptRequireBitAnd: map[FheUintType]uint64{
			FheUint4:  20000,
			FheUint8:  20000,
			FheUint16: 20000,
			FheUint32: 20000,
		},
		FheGetCiphertext: map[FheUintType]uint64{
			FheUint8:  12000,
			FheUint16: 14000,
			FheUint32: 18000,
			FheUint64: 28000,
		},
	}
}

var TxDataFractionalGasFactor uint64 = 4

func TxDataFractionalGas(originalGas uint64) (fractionalGas uint64) {
	return originalGas / TxDataFractionalGasFactor
}
