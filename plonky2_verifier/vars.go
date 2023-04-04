package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

type HashOut struct {
	elements [4]F
}

type EvaluationVars struct {
	localConstants   []QuadraticExtension
	localWires       []QuadraticExtension
	publicInputsHash HashOut
}

func (e *EvaluationVars) RemovePrefix(numSelectors int) {
	e.localConstants = e.localConstants[numSelectors:]
}
