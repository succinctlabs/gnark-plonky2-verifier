package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

type EvaluationVars struct {
	localConstants   []QuadraticExtension
	localWires       []QuadraticExtension
	publicInputsHash Hash
}

func (e *EvaluationVars) RemovePrefix(numSelectors uint64) {
	e.localConstants = e.localConstants[numSelectors:]
}

func (e *EvaluationVars) GetLocalExtAlgebra(wireRange Range) QEAlgebra {
	// For now, only support degree 2
	if wireRange.end-wireRange.start != D {
		panic("Range must be of size D")
	}

	var ret QEAlgebra
	for i := wireRange.start; i < wireRange.end; i++ {
		ret[i-wireRange.start] = e.localWires[i]
	}

	return ret
}
