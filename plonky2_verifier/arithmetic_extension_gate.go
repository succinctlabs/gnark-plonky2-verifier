package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"
)

type ArithmeticExtensionGate struct {
	numOps uint64
}

func NewArithmeticExtensionGate(numOps uint64) *ArithmeticExtensionGate {
	return &ArithmeticExtensionGate{
		numOps: numOps,
	}
}

func (g *ArithmeticExtensionGate) Id() string {
	return fmt.Sprintf("ArithmeticExtensionGate { num_ops: %d }", g.numOps)
}

func (g *ArithmeticExtensionGate) wiresIthMultiplicand0(i uint64) Range {
	return Range{4 * field.D * i, 4*field.D*i + field.D}
}

func (g *ArithmeticExtensionGate) wiresIthMultiplicand1(i uint64) Range {
	return Range{4*field.D*i + field.D, 4*field.D*i + 2*field.D}
}

func (g *ArithmeticExtensionGate) wiresIthAddend(i uint64) Range {
	return Range{4*field.D*i + 2*field.D, 4*field.D*i + 3*field.D}
}

func (g *ArithmeticExtensionGate) wiresIthOutput(i uint64) Range {
	return Range{4*field.D*i + 3*field.D, 4*field.D*i + 4*field.D}
}

func (g *ArithmeticExtensionGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	const0 := vars.localConstants[0]
	const1 := vars.localConstants[1]

	constraints := []field.QuadraticExtension{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand0(i))
		multiplicand1 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand1(i))
		addend := vars.GetLocalExtAlgebra(g.wiresIthAddend(i))
		output := vars.GetLocalExtAlgebra(g.wiresIthOutput(i))

		mul := p.qeAPI.MulExtensionAlgebra(multiplicand0, multiplicand1)
		scaled_mul := p.qeAPI.ScalarMulExtensionAlgebra(const0, mul)
		computed_output := p.qeAPI.ScalarMulExtensionAlgebra(const1, addend)
		computed_output = p.qeAPI.AddExtensionAlgebra(computed_output, scaled_mul)

		diff := p.qeAPI.SubExtensionAlgebra(output, computed_output)
		for j := 0; j < field.D; j++ {
			constraints = append(constraints, diff[j])
		}
	}

	return constraints
}
