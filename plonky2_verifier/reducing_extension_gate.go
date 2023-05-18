package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

type ReducingExtensionGate struct {
	numCoeffs uint64
}

const START_COEFFS = 3 * D

func NewReducingExtensionGate(numCoeffs uint64) *ReducingExtensionGate {
	return &ReducingExtensionGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingExtensionGate) Id() string {
	return fmt.Sprintf("ReducingExtensionGate { num_ops: %d }", g.numCoeffs)
}

func (g *ReducingExtensionGate) wiresOutput() Range {
	return Range{0, D}
}

func (g *ReducingExtensionGate) wiresAlpha() Range {
	return Range{D, 2 * D}
}

func (g *ReducingExtensionGate) wiresOldAcc() Range {
	return Range{2 * D, 3 * D}
}

func (g *ReducingExtensionGate) wiresCoeff(i uint64) Range {
	return Range{START_COEFFS + D*i, START_COEFFS + D*(i+1)}
}

func (g *ReducingExtensionGate) startAccs() uint64 {
	return START_COEFFS + g.numCoeffs*D
}

func (g *ReducingExtensionGate) wiresAccs(i uint64) Range {
	if i >= g.numCoeffs {
		panic("Accumulator index out of bounds")
	}

	if i == g.numCoeffs-1 {
		return g.wiresOutput()
	}

	return Range{g.startAccs() + D*i, g.startAccs() + D*(i+1)}
}

func (g *ReducingExtensionGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeffs = append(coeffs, vars.GetLocalExtAlgebra(g.wiresCoeff(i)))
	}

	accs := []QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []QuadraticExtension{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeff := coeffs[i]
		tmp := p.qeAPI.MulExtensionAlgebra(acc, alpha)
		tmp = p.qeAPI.AddExtensionAlgebra(tmp, coeff)
		tmp = p.qeAPI.SubExtensionAlgebra(tmp, accs[i])
		for j := uint64(0); j < D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
