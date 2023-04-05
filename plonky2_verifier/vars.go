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
