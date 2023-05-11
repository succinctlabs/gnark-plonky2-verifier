package utils

import (
	. "gnark-plonky2-verifier/field"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func StrArrayToBigIntArray(input []string) []big.Int {
	var output []big.Int
	for i := 0; i < len(input); i++ {
		a := new(big.Int)
		a, _ = a.SetString(input[i], 10)
		output = append(output, *a)
	}
	return output
}

func StrArrayToFrontendVariableArray(input []string) []frontend.Variable {
	var output []frontend.Variable
	for i := 0; i < len(input); i++ {
		output = append(output, frontend.Variable(input[i]))
	}
	return output
}

func StrArrayToFieldArray(input []string) []FTarget {
	var output []FTarget
	for i := 0; i < len(input); i++ {
		output = append(output, *NewFieldConstFromString(input[i]))
	}
	return output
}

func Uint64ArrayToFArray(input []uint64) []*FTarget {
	var output []*FTarget
	for i := 0; i < len(input); i++ {
		output = append(output, NewFieldConst(input[i]))
	}
	return output
}

func Uint64ArrayToQuadraticExtension(input []uint64) *QETarget {
	return NewQuadraticExtensionTarget(NewFieldConst(input[0]), NewFieldConst(input[1]))
}

func Uint64ArrayToQuadraticExtensionArray(input [][]uint64) []*QETarget {
	var output []*QETarget
	for i := 0; i < len(input); i++ {
		output = append(output, NewQuadraticExtensionTarget(NewFieldConst(input[i][0]), NewFieldConst(input[i][1])))
	}
	return output
}

/*
func Uint64ArrayToHashArray(input [][]uint64) []Hash {
	var output []Hash
	for i := 0; i < len(input); i++ {
		output = append(output, [4]F{NewFieldConst(input[i][0]), NewFieldConst(input[i][1]), NewFieldConst(input[i][2]), NewFieldConst(input[i][3])})
	}
	return output
}
*/
