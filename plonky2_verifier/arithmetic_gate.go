package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"
)

type ArithmeticGate struct {
	numOps uint64
}

func NewArithmeticGate(numOps uint64) *ArithmeticGate {
	return &ArithmeticGate{
		numOps: numOps,
	}
}

func (g *ArithmeticGate) Id() string {
	return fmt.Sprintf("ArithmeticGate { num_ops: %d }", g.numOps)
}

func (g *ArithmeticGate) WireIthMultiplicand0(i uint64) uint64 {
	return 4 * i
}

func (g *ArithmeticGate) WireIthMultiplicand1(i uint64) uint64 {
	return 4*i + 1
}

func (g *ArithmeticGate) WireIthAddend(i uint64) uint64 {
	return 4*i + 2
}

func (g *ArithmeticGate) WireIthOutput(i uint64) uint64 {
	return 4*i + 3
}

func (g *ArithmeticGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	const0 := vars.localConstants[0]
	const1 := vars.localConstants[1]

	constraints := []field.QuadraticExtension{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.localWires[g.WireIthMultiplicand0(i)]
		multiplicand1 := vars.localWires[g.WireIthMultiplicand1(i)]
		addend := vars.localWires[g.WireIthAddend(i)]
		output := vars.localWires[g.WireIthOutput(i)]

		computedOutput := p.qeAPI.AddExtension(
			p.qeAPI.MulExtension(p.qeAPI.MulExtension(multiplicand0, multiplicand1), const0),
			p.qeAPI.MulExtension(addend, const1),
		)

		constraints = append(constraints, p.qeAPI.SubExtension(output, computedOutput))
	}

	return constraints
}
