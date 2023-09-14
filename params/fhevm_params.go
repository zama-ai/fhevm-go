package params

import evm "github.com/ethereum/go-ethereum/params"

var (
	// FHE operation costs depend on tfhe-rs performance and hardware acceleration. These values will most certainly change.
	FheUint8AddSubGas   uint64 = 83000
	FheUint16AddSubGas  uint64 = 108000
	FheUint32AddSubGas  uint64 = 130000
	FheUint8MulGas      uint64 = 150000
	FheUint16MulGas     uint64 = 200000
	FheUint32MulGas     uint64 = 270000
	FheUint8DivGas      uint64 = 1370000
	FheUint16DivGas     uint64 = 3500000
	FheUint32DivGas     uint64 = 9120000
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
	FheUint8ReencryptGas  uint64 = 1000
	FheUint16ReencryptGas uint64 = 1100
	FheUint32ReencryptGas uint64 = 1200
	FheUint8DecryptGas    uint64 = 600
	FheUint16DecryptGas   uint64 = 700
	FheUint32DecryptGas   uint64 = 800

	// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
	FheUint8VerifyGas  uint64 = 200
	FheUint16VerifyGas uint64 = 300
	FheUint32VerifyGas uint64 = 400

	// TODO: Cost will depend on the complexity of doing decryption by the oracle.
	FheUint8RequireGas  uint64 = 170000
	FheUint16RequireGas uint64 = 180000
	FheUint32RequireGas uint64 = 190000

	// TODO: As of now, only support FheUint8. All optimistic require predicates are
	// downcast to FheUint8 at the solidity level. Eventually move to ebool.
	// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
	// For every subsequent optimistic require, we need to bitand it with the current require value - that
	// works, because we assume requires have a value of 0 or 1.
	FheUint8OptimisticRequireGas       uint64 = FheUint8RequireGas
	FheUint8OptimisticRequireBitandGas uint64 = FheUint8BitwiseGas

	// TODO: This will change once we have an FHE-based random generaration with different types.
	FheRandGas uint64 = evm.NetSstoreCleanGas + evm.ColdSloadCostEIP2929

	// TODO: The values here are chosen somewhat arbitrarily (at least the 8 bit ones). Also, we don't
	// take into account whether a ciphertext existed (either "current" or "original") for the given handle.
	// Finally, costs are likely to change in the future.
	FheUint8ProtectedStorageSstoreGas  uint64 = evm.NetSstoreInitGas + 2000
	FheUint16ProtectedStorageSstoreGas uint64 = FheUint8ProtectedStorageSstoreGas * 2
	FheUint32ProtectedStorageSstoreGas uint64 = FheUint16ProtectedStorageSstoreGas * 2

	// TODO: We don't take whether the slot is cold or warm into consideration.
	FheUint8ProtectedStorageSloadGas  uint64 = evm.ColdSloadCostEIP2929 + 200
	FheUint16ProtectedStorageSloadGas uint64 = FheUint8ProtectedStorageSloadGas * 2
	FheUint32ProtectedStorageSloadGas uint64 = FheUint16ProtectedStorageSloadGas * 2

	FheCastGas uint64 = 100

	FhePubKeyGas uint64 = 2

	FheUint8TrivialEncryptGas  uint64 = 100
	FheUint16TrivialEncryptGas uint64 = 200
	FheUint32TrivialEncryptGas uint64 = 400
)
