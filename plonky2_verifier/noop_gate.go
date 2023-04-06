package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

type NoopGate struct {
}

func (p *NoopGate) EvalUnfiltered(pc *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	return []QuadraticExtension{}
}
