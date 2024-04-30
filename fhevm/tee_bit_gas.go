package fhevm

func teeShiftRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeShift", environment, input, environment.FhevmParams().GasCosts.TeeShift)
}

func teeBitwiseOpRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeBitwiseOp", environment, input, environment.FhevmParams().GasCosts.TeeBitwiseOp)
}

func teeNotRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeNot", environment, input, environment.FhevmParams().GasCosts.TeeNot)
}

func teeNegRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeNeg", environment, input, environment.FhevmParams().GasCosts.TeeNeg)
}
