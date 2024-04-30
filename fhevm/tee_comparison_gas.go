package fhevm

func teeComparisonRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return teeOperationGas("teeComparison", environment, input, environment.FhevmParams().GasCosts.TeeComparison)
}
