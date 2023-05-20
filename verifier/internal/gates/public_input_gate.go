package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var publicInputGateRegex = regexp.MustCompile("PublicInputGate")

func deserializePublicInputGate(parameters map[string]string) Gate {
	// Has the format "PublicInputGate"
	return NewPublicInputGate()
}

type PublicInputGate struct {
}

func NewPublicInputGate() *PublicInputGate {
	return &PublicInputGate{}
}

func (g *PublicInputGate) Id() string {
	return "PublicInputGate"
}

func (g *PublicInputGate) WiresPublicInputsHash() []uint64 {
	return []uint64{0, 1, 2, 3}
}

func (g *PublicInputGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	constraints := []field.QuadraticExtension{}

	wires := g.WiresPublicInputsHash()
	hash_parts := vars.publicInputsHash
	for i := 0; i < 4; i++ {
		wire := wires[i]
		hash_part := hash_parts[i]

		diff := qeAPI.SubExtension(vars.localWires[wire], qeAPI.FieldToQE(hash_part))
		constraints = append(constraints, diff)
	}

	return constraints
}
