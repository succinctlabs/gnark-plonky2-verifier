package utils

import (
	. "gnark-ed25519/goldilocks"
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

func Uint64ArrayToGoldilocksElementArray(input []uint64) []GoldilocksElement {
	var output []GoldilocksElement
	for i := 0; i < len(input); i++ {
		output = append(output, emulated.NewElement[emulated.Goldilocks](input[i]))
	}
	return output
}
