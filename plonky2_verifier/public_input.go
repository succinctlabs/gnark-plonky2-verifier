package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

type PublicInputGate struct {
}

func (p *PublicInputGate) WiresPublicInputsHash() []int {
	return []int{0, 1, 2, 3}
}

func (p *PublicInputGate) EvalUnfiltered(pc *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}

	wires := p.WiresPublicInputsHash()
	hash_parts := vars.publicInputsHash.elements
	for i := 0; i < 4; i++ {
		wire := wires[i]
		hash_part := hash_parts[i]

		diff := pc.qeAPI.SubExtension(vars.localWires[wire], pc.qeAPI.FieldToQE(hash_part))
		constraints = append(constraints, diff)
	}

	return constraints
}

func (p *PublicInputGate) EvalFiltered(vars EvaluationVars) []QuadraticExtension {
	return nil
}
