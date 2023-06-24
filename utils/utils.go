package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/gl"
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

func Uint64ArrayToFArray(input []uint64) []gl.Variable {
	var output []gl.Variable
	for i := 0; i < len(input); i++ {
		output = append(output, gl.NewVariable(input[i]))
	}
	return output
}

func Uint64ArrayToQuadraticExtension(input []uint64) gl.QuadraticExtensionVariable {
	return gl.NewQuadraticExtensionVariable(gl.NewVariable(input[0]), gl.NewVariable(input[1]))
}

func Uint64ArrayToQuadraticExtensionArray(input [][]uint64) []gl.QuadraticExtensionVariable {
	var output []gl.QuadraticExtensionVariable
	for i := 0; i < len(input); i++ {
		output = append(output, gl.NewQuadraticExtensionVariable(gl.NewVariable(input[i][0]), gl.NewVariable(input[i][1])))
	}
	return output
}
