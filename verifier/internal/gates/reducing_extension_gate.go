package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var reducingExtensionGateRegex = regexp.MustCompile("ReducingExtensionGate { num_coeffs: (?P<numCoeffs>[0-9]+) }")

func deserializeReducingExtensionGate(parameters map[string]string) Gate {
	// Has the format "ReducingGate { num_coeffs: 33 }"
	numCoeffs, hasNumCoeffs := parameters["numCoeffs"]
	if !hasNumCoeffs {
		panic("Missing field num_coeffs in ReducingExtensionGate")
	}

	numCoeffsInt, err := strconv.Atoi(numCoeffs)
	if err != nil {
		panic("Invalid num_coeffs field in ReducingExtensionGate")
	}

	return NewReducingExtensionGate(uint64(numCoeffsInt))
}

type ReducingExtensionGate struct {
	numCoeffs uint64
}

const START_COEFFS_REDUCING_EXTENSION_GATE = 3 * field.D

func NewReducingExtensionGate(numCoeffs uint64) *ReducingExtensionGate {
	return &ReducingExtensionGate{
		numCoeffs: numCoeffs,
	}
}

func (g *ReducingExtensionGate) Id() string {
	return fmt.Sprintf("ReducingExtensionGate { num_ops: %d }", g.numCoeffs)
}

func (g *ReducingExtensionGate) wiresOutput() Range {
	return Range{0, field.D}
}

func (g *ReducingExtensionGate) wiresAlpha() Range {
	return Range{field.D, 2 * field.D}
}

func (g *ReducingExtensionGate) wiresOldAcc() Range {
	return Range{2 * field.D, 3 * field.D}
}

func (g *ReducingExtensionGate) wiresCoeff(i uint64) Range {
	return Range{START_COEFFS_REDUCING_EXTENSION_GATE + field.D*i, START_COEFFS_REDUCING_EXTENSION_GATE + field.D*(i+1)}
}

func (g *ReducingExtensionGate) startAccs() uint64 {
	return START_COEFFS_REDUCING_EXTENSION_GATE + g.numCoeffs*field.D
}

func (g *ReducingExtensionGate) wiresAccs(i uint64) Range {
	if i >= g.numCoeffs {
		panic("Accumulator index out of bounds")
	}

	if i == g.numCoeffs-1 {
		return g.wiresOutput()
	}

	return Range{g.startAccs() + field.D*i, g.startAccs() + field.D*(i+1)}
}

func (g *ReducingExtensionGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	alpha := vars.GetLocalExtAlgebra(g.wiresAlpha())
	oldAcc := vars.GetLocalExtAlgebra(g.wiresOldAcc())

	coeffs := []field.QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeffs = append(coeffs, vars.GetLocalExtAlgebra(g.wiresCoeff(i)))
	}

	accs := []field.QEAlgebra{}
	for i := uint64(0); i < g.numCoeffs; i++ {
		accs = append(accs, vars.GetLocalExtAlgebra(g.wiresAccs(i)))
	}

	constraints := []field.QuadraticExtension{}
	acc := oldAcc
	for i := uint64(0); i < g.numCoeffs; i++ {
		coeff := coeffs[i]
		tmp := qeAPI.MulExtensionAlgebra(acc, alpha)
		tmp = qeAPI.AddExtensionAlgebra(tmp, coeff)
		tmp = qeAPI.SubExtensionAlgebra(tmp, accs[i])
		for j := uint64(0); j < field.D; j++ {
			constraints = append(constraints, tmp[j])
		}
		acc = accs[i]
	}

	return constraints
}
