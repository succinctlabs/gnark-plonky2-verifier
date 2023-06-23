package gates

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/gl"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type EvaluationVars struct {
	localConstants   []gl.QuadraticExtensionVariable
	localWires       []gl.QuadraticExtensionVariable
	publicInputsHash poseidon.PoseidonHashOut
}

func NewEvaluationVars(
	localConstants []gl.QuadraticExtensionVariable,
	localWires []gl.QuadraticExtensionVariable,
	publicInputsHash poseidon.PoseidonHashOut,
) *EvaluationVars {
	return &EvaluationVars{
		localConstants:   localConstants,
		localWires:       localWires,
		publicInputsHash: publicInputsHash,
	}
}

func (e *EvaluationVars) RemovePrefix(numSelectors uint64) {
	e.localConstants = e.localConstants[numSelectors:]
}

func (e *EvaluationVars) GetLocalExtAlgebra(wireRange Range) gl.QuadraticExtensionAlgebraVariable {
	// For now, only support degree 2
	if wireRange.end-wireRange.start != field.D {
		panic("Range must be of size D")
	}

	var ret gl.QuadraticExtensionAlgebraVariable
	for i := wireRange.start; i < wireRange.end; i++ {
		ret[i-wireRange.start] = e.localWires[i]
	}

	return ret
}
