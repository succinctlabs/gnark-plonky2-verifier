package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
	"regexp"
)

var publicInputGateRegex = regexp.MustCompile("PublicInputGate")

func deserializePublicInputGate(parameters map[string]string) gate {
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

func (g *PublicInputGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}

	wires := g.WiresPublicInputsHash()
	hash_parts := vars.publicInputsHash
	for i := 0; i < 4; i++ {
		wire := wires[i]
		hash_part := hash_parts[i]

		diff := p.qeAPI.SubExtension(vars.localWires[wire], p.qeAPI.FieldToQE(hash_part))
		constraints = append(constraints, diff)
	}

	return constraints
}
