package fhevm

import (
	"math/big"

	"github.com/zama-ai/fhevm-go/pkg/tfhe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const operandTypeAttrName = "operand_types"

// The operand interface is used to get the string
// representation of any operand that comes in,either
// it's encrypted or not
type operand interface {
	typeName() string
}

type plainOperand big.Int
type encryptedOperand verifiedCiphertext

func (plainOperand) typeName() string {
	return "plainScalar"
}

func (op encryptedOperand) typeName() string {
	ct := verifiedCiphertext(op)
	return ct.fheUintType().String()
}

func otelDescribeOperands(span trace.Span, operands ...operand) {
	if span == nil {
		return
	}
	var operandTypes string
	for i, ot := range operands {
		operandTypes += ot.typeName()
		if i < len(operands)-1 {
			operandTypes += ","
		}
	}
	span.SetAttributes(attribute.KeyValue{Key: operandTypeAttrName, Value: attribute.StringValue(operandTypes)})
}

func otelDescribeOperandsFheTypes(span trace.Span, types ...tfhe.FheUintType) {
	if span == nil {
		return
	}
	var operandTypes string
	for i, t := range types {
		operandTypes += t.String()
		if i < len(types)-1 {
			operandTypes += ","
		}
	}
	span.SetAttributes(attribute.KeyValue{Key: operandTypeAttrName, Value: attribute.StringValue(operandTypes)})
}
