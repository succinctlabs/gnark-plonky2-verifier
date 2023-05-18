package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

type ReducingGate struct {
	numCoeffs uint64
}

const START_COEFFS_REDUCING_GATE = 3 * D

func NewReducingGate(numCoeffs uint64) *ReducingGate {
	return &ReducingGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingGate) Id() string {
	return fmt.Sprintf("ReducingExtensionGate { num_ops: %d }", g.numCoeffs)
}

func (g *ReducingGate) wiresOutput() Range {
	return Range{0, D}
}

func (g *ReducingGate) wiresAlpha() Range {
	return Range{D, 2 * D}
}

func (g *ReducingGate) wiresOldAcc() Range {
	return Range{2 * D, 3 * D}
}

func (g *ReducingGate) wiresCoeff() Range {
	return Range{START_COEFFS_REDUCING_GATE, START_COEFFS_REDUCING_GATE + g.numCoeffs}
}

func (g *ReducingGate) startAccs() uint64 {
	return START_COEFFS_REDUCING_GATE + g.numCoeffs
}

func (g *ReducingGate) wiresAccs(i uint64) Range {
	if i >= g.numCoeffs {
		panic("Accumulator index out of bounds")
	}

	if i == g.numCoeffs-1 {
		return g.wiresOutput()
	}

	return Range{g.startAccs() + D*i, g.startAccs() + D*(i+1)}
}

func (g *ReducingGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []QuadraticExtension{}
	coeffsRange := g.wiresCoeff()
	for i := coeffsRange.start; i < coeffsRange.end; i++ {
		coeffs = append(coeffs, vars.localWires[i])
	}

	accs := []QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []QuadraticExtension{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		var coeff QEAlgebra
		for j := 0; j < D; j++ {
			coeff[j] = p.qeAPI.ZERO_QE
		}
		coeff[0] = coeffs[i]
		tmp := p.qeAPI.MulExtensionAlgebra(acc, alpha)
		tmp = p.qeAPI.AddExtensionAlgebra(tmp, coeff)
		tmp = p.qeAPI.SubExtensionAlgebra(tmp, accs[i])
		for j := 0; j < D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
