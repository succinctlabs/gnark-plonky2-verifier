package gates

import (
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

// EvaluationVars stores variables for gate evaluations in a quadratic extension field.
type EvaluationVars struct {
	localConstants   []gl.QuadraticExtensionVariable // Constants local to the gate evaluation
	localWires       []gl.QuadraticExtensionVariable // Wires representing local variables
	publicInputsHash poseidon.GoldilocksHashOut      // Hash of the public inputs
}

func NewEvaluationVars(
	localConstants []gl.QuadraticExtensionVariable,
	localWires []gl.QuadraticExtensionVariable,
	publicInputsHash poseidon.GoldilocksHashOut,
) *EvaluationVars {
	return &EvaluationVars{
		localConstants:   localConstants,
		localWires:       localWires,
		publicInputsHash: publicInputsHash,
	}
}

// RemovePrefix removes the first `numSelectors` elements from localConstants.
func (e *EvaluationVars) RemovePrefix(numSelectors uint64) {
	e.localConstants = e.localConstants[numSelectors:]
}

// GetLocalExtAlgebra retrieves a subrange of local wires as a quadratic extension algebra variable.
func (e *EvaluationVars) GetLocalExtAlgebra(wireRange Range) gl.QuadraticExtensionAlgebraVariable {
	// For now, only support degree 2
	if wireRange.end-wireRange.start != gl.D {
		panic("Range must be of size D")
	}

	var ret gl.QuadraticExtensionAlgebraVariable
	for i := wireRange.start; i < wireRange.end; i++ {
		ret[i-wireRange.start] = e.localWires[i]
	}

	return ret
}
