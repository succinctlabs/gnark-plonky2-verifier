package plonky2_verifier

import (
	"gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"
)

type EvaluationVars struct {
	localConstants   []field.QuadraticExtension
	localWires       []field.QuadraticExtension
	publicInputsHash poseidon.Hash
}

func (e *EvaluationVars) RemovePrefix(numSelectors uint64) {
	e.localConstants = e.localConstants[numSelectors:]
}

func (e *EvaluationVars) GetLocalExtAlgebra(wireRange Range) field.QEAlgebra {
	// For now, only support degree 2
	if wireRange.end-wireRange.start != field.D {
		panic("Range must be of size D")
	}

	var ret field.QEAlgebra
	for i := wireRange.start; i < wireRange.end; i++ {
		ret[i-wireRange.start] = e.localWires[i]
	}

	return ret
}
