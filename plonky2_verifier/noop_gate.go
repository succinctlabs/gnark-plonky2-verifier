package plonky2_verifier

import (
	"gnark-plonky2-verifier/field"
	"regexp"
)

var noopGateRegex = regexp.MustCompile("NoopGate")

func deserializeNoopGate(parameters map[string]string) gate {
	// Has the format "NoopGate"
	return NewNoopGate()
}

type NoopGate struct {
}

func NewNoopGate() *NoopGate {
	return &NoopGate{}
}

func (g *NoopGate) Id() string {
	return "NoopGate"
}

func (g *NoopGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	return []field.QuadraticExtension{}
}
