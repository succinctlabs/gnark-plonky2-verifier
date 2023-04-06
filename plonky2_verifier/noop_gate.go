package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

type NoopGate struct {
}

func NewNoopGate() *NoopGate {
	return &NoopGate{}
}

func (g *NoopGate) Id() string {
	return "NoopGate"
}

func (g *NoopGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	return []QuadraticExtension{}
}
