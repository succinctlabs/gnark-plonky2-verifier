package utils

import (
	. "gnark-ed25519/field"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
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
		output = append(output, emulated.NewElement[emulated.Goldilocks](input[i]))
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
