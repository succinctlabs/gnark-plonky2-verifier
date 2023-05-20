package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var noopGateRegex = regexp.MustCompile("NoopGate")

func deserializeNoopGate(parameters map[string]string) Gate {
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

func (g *NoopGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	return []field.QuadraticExtension{}
}
