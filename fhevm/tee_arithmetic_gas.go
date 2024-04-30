package fhevm

func teeAddSubRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeAddSub", environment, input, environment.FhevmParams().GasCosts.TeeAddSub)
}

func teeMulRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeMul", environment, input, environment.FhevmParams().GasCosts.TeeMul)
}

func teeDivRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeDiv", environment, input, environment.FhevmParams().GasCosts.TeeDiv)
}

func teeRemRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeRem", environment, input, environment.FhevmParams().GasCosts.TeeRem)
}
