package utils

import (
	. "gnark-ed25519/field"
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

func Uint64ArrayToFArray(input []uint64) []F {
	var output []F
	for i := 0; i < len(input); i++ {
		output = append(output, NewFieldElement(input[i]))
	}
	return output
}

func Uint64ArrayToQuadraticExtensionArray(input [][]uint64) []QuadraticExtension {
	var output []QuadraticExtension
	for i := 0; i < len(input); i++ {
		output = append(output, [2]F{NewFieldElement(input[i][0]), NewFieldElement(input[i][1])})
	}
	return output
}

func Uint64ArrayToHashArray(input [][]uint64) []Hash {
	var output []Hash
	for i := 0; i < len(input); i++ {
		output = append(output, [4]F{NewFieldElement(input[i][0]), NewFieldElement(input[i][1]), NewFieldElement(input[i][2]), NewFieldElement(input[i][3])})
	}
	return output
}
