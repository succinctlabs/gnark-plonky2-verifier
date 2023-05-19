package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"
	"regexp"
	"strconv"
)

var reducingGateRegex = regexp.MustCompile("ReducingGate { num_coeffs: (?P<numCoeffs>[0-9]+) }")

func deserializeReducingGate(parameters map[string]string) gate {
	// Has the format "ReducingGate { num_coeffs: 33 }"
	numCoeffs, hasNumCoeffs := parameters["numCoeffs"]
	if !hasNumCoeffs {
		panic("Missing field num_coeffs in ReducingGate")
	}

	numCoeffsInt, err := strconv.Atoi(numCoeffs)
	if err != nil {
		panic("Invalid num_coeffs field in ReducingGate")
	}

	return NewReducingGate(uint64(numCoeffsInt))
}

type ReducingGate struct {
	numCoeffs uint64
}

const START_COEFFS_REDUCING_GATE = 3 * field.D

func NewReducingGate(numCoeffs uint64) *ReducingGate {
	return &ReducingGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingGate) Id() string {
	return fmt.Sprintf("ReducingExtensionGate { num_ops: %d }", g.numCoeffs)
}

func (g *ReducingGate) wiresOutput() Range {
	return Range{0, field.D}
}

func (g *ReducingGate) wiresAlpha() Range {
	return Range{field.D, 2 * field.D}
}

func (g *ReducingGate) wiresOldAcc() Range {
	return Range{2 * field.D, 3 * field.D}
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

	return Range{g.startAccs() + field.D*i, g.startAccs() + field.D*(i+1)}
}

func (g *ReducingGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []field.QuadraticExtension{}
	coeffsRange := g.wiresCoeff()
	for i := coeffsRange.start; i < coeffsRange.end; i++ {
		coeffs = append(coeffs, vars.localWires[i])
	}

	accs := []field.QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []field.QuadraticExtension{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		var coeff field.QEAlgebra
		for j := 0; j < field.D; j++ {
			coeff[j] = p.qeAPI.ZERO_QE
		}
		coeff[0] = coeffs[i]
		tmp := p.qeAPI.MulExtensionAlgebra(acc, alpha)
		tmp = p.qeAPI.AddExtensionAlgebra(tmp, coeff)
		tmp = p.qeAPI.SubExtensionAlgebra(tmp, accs[i])
		for j := 0; j < field.D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
