package fhevm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
)

func teeShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOp(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case tfhe.FheUint4:
			a1, b1 := uint8(a), uint8(b)%4
			return uint64(a1<<b1) & 0x0F, nil
		case tfhe.FheUint8:
			a1, b1 := uint8(a), uint8(b)%8
			return uint64(a1 << b1), nil
		case tfhe.FheUint16:
			a1, b1 := uint16(a), uint16(b)%16
			return uint64(a1 << b1), nil
		case tfhe.FheUint32:
			a1, b1 := uint32(a), uint32(b)%32
			return uint64(a1 << b1), nil
		case tfhe.FheUint64:
			return a << (b % 64), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeShlRun")
}

func teeShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOp(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case tfhe.FheUint4:
			a1, b1 := uint8(a), uint8(b)%4
			return uint64(a1 >> b1), nil
		case tfhe.FheUint8:
			a1, b1 := uint8(a), uint8(b)%8
			return uint64(a1 >> b1), nil
		case tfhe.FheUint16:
			a1, b1 := uint16(a), uint16(b)%16
			return uint64(a1 >> b1), nil
		case tfhe.FheUint32:
			a1, b1 := uint32(a), uint32(b)%32
			return uint64(a1 >> b1), nil
		case tfhe.FheUint64:
			return a >> (b % 64), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeShrRun")
}

func teeRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOp(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		// Rotate the bits of 'a' to the right by 'b' positions.
		// '(a >> b)' shifts bits to the right, discarding bits shifted out.
		// '(a << (typ - b))' shifts bits to the left by 'typ - b' positions, effectively moving the discarded bits from the right shift to the left end.
		// The bitwise OR '|' combines these two operations, achieving a right rotation of 'b' positions.
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case tfhe.FheUint4:
			a1, b1 := uint8(a), uint8(b)%4
			return uint64((a1<<b1)|(a1>>(uint8(4)-b1))) & 0x0F, nil
		case tfhe.FheUint8:
			a1, b1 := uint8(a), uint8(b)%8
			return uint64((a1 << b1) | (a1 >> (uint8(8) - b1))), nil
		case tfhe.FheUint16:
			a1, b1 := uint16(a), uint16(b)%16
			return uint64((a1 << b1) | (a1 >> (uint16(16) - b1))), nil
		case tfhe.FheUint32:
			a1, b1 := uint32(a), uint32(b)%32
			return uint64((a1 << b1) | (a1 >> (uint32(32) - b1))), nil
		case tfhe.FheUint64:
			return (a << (b % 64)) | (a >> (64 - b%64)), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeRotl")
}

func teeRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doShiftOp(environment, caller, input, runSpan, func(a, b uint64, typ tfhe.FheUintType) (uint64, error) {
		// Rotate the bits of 'a' to the left by 'b' positions.
		// '(a << b)' shifts bits to the left, moving bits towards the most significant bit (left end) and discarding bits that fall off the left end.
		// '(a >> (typ - b))' shifts bits to the right by 'typ - b' positions, effectively moving the discarded bits from the left shift to the right end.
		// The bitwise OR '|' operation combines these two shifted values, achieving a left rotation of 'b' positions on 'a'.
		switch typ {
		// There isn't bitwise shift operation between ebool. So it doesn't include case 0.
		case tfhe.FheUint4:
			a1, b1 := uint8(a), uint8(b)%4
			return uint64((a1>>b1)|(a1<<(uint8(4)-b1))) & 0x0F, nil
		case tfhe.FheUint8:
			a1, b1 := uint8(a), uint8(b)%8
			return uint64((a1 >> b1) | (a1 << (uint8(8) - b1))), nil
		case tfhe.FheUint16:
			a1, b1 := uint16(a), uint16(b)%16
			return uint64((a1 >> b1) | (a1 << (uint16(16) - b1))), nil
		case tfhe.FheUint32:
			a1, b1 := uint32(a), uint32(b)%32
			return uint64((a1 >> b1) | (a1 << (uint32(32) - b1))), nil
		case tfhe.FheUint64:
			return (a >> (b % 64)) | (a << (64 - b%64)), nil
		default:
			return 0, fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	}, "teeRotr")
}

func teeBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a & b
	}, "teeBitAnd")
}

func teeBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a | b
	}, "teeBitOr")
}

func teeBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doOp(environment, caller, input, runSpan, func(a, b uint64) uint64 {
		return a ^ b
	}, "teeBitXor")
}

func teeNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOp(environment, caller, input, runSpan, func(a uint64) uint64 {
		return ^a + 1
	}, "teeNeg")
}

func teeNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return doNegNotOp(environment, caller, input, runSpan, func(a uint64) uint64 {
		return ^a
	}, "teeNot")
}
