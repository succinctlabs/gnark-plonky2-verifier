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
	if wireRange.end-wireRange.start != 2 {
		panic("Only degree 2 supported")
	}

	return QEAlgebra{e.localWires[wireRange.start], e.localWires[wireRange.end]}
}
