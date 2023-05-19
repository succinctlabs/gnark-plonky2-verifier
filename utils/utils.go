package utils

import (
	"gnark-plonky2-verifier/field"
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

func Uint64ArrayToFArray(input []uint64) []field.F {
	var output []field.F
	for i := 0; i < len(input); i++ {
		output = append(output, field.NewFieldElement(input[i]))
	}
	return output
}

func Uint64ArrayToQuadraticExtension(input []uint64) field.QuadraticExtension {
	return [2]field.F{field.NewFieldElement(input[0]), field.NewFieldElement(input[1])}
}

func Uint64ArrayToQuadraticExtensionArray(input [][]uint64) []field.QuadraticExtension {
	var output []field.QuadraticExtension
	for i := 0; i < len(input); i++ {
		output = append(output, [2]field.F{field.NewFieldElement(input[i][0]), field.NewFieldElement(input[i][1])})
	}
	return output
}
