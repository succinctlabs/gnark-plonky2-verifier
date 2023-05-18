package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

type CosetInterpolationGate struct {
	subgroupBits       uint64
	degree             uint64
	barycentricWeights []uint64
}

func NewCosetInterpolationGate(subgroupBits uint64, degree uint64, barycentricWeights []uint64) *CosetInterpolationGate {
	return &CosetInterpolationGate{
		subgroupBits:       subgroupBits,
		degree:             degree,
		barycentricWeights: barycentricWeights,
	}
}

func (g *CosetInterpolationGate) Id() string {

	return fmt.Sprintf(
		"CosetInterpolationGate { subgroup_bits: %d, degree: %d, barycentric_weights: %s }",
		g.subgroupBits,
		g.degree,
		fmt.Sprint(g.barycentricWeights),
	)
}

func (g *CosetInterpolationGate) numPoints() uint64 {
	return 1 << g.subgroupBits
}

// Wire index of the coset shift.
func (g *CosetInterpolationGate) wireShift() uint64 {
	return 0
}

func (g *CosetInterpolationGate) startValues() uint64 {
	return 1
}

// Wire indices of the `i`th interpolant value.
func (g *CosetInterpolationGate) wiresValue(i uint64) Range {
	if i >= g.numPoints() {
		panic("Invalid point index")
	}
	start := g.startValues() + i*D
	return Range{start, start + D}
}

func (g *CosetInterpolationGate) startEvaluationPoint() uint64 {
	return g.startValues() + g.numPoints()*D
}

// Wire indices of the point to evaluate the interpolant at.
func (g *CosetInterpolationGate) wiresEvaluationPoint() Range {
	start := g.startEvaluationPoint()
	return Range{start, start + D}
}

func (g *CosetInterpolationGate) startEvaluationValue() uint64 {
	return g.startEvaluationPoint() + D
}

// Wire indices of the interpolated value.
func (g *CosetInterpolationGate) wiresEvaluationValue() Range {
	start := g.startEvaluationValue()
	return Range{start, start + D}
}

func (g *CosetInterpolationGate) startIntermediates() uint64 {
	return g.startEvaluationValue() + D
}

func (g *CosetInterpolationGate) numRoutedWires() uint64 {
	return g.startIntermediates()
}

func (g *CosetInterpolationGate) numIntermediates() uint64 {
	return (g.numPoints() - 2) / (g.degree - 1)
}

// The wires corresponding to the i'th intermediate evaluation.
func (g *CosetInterpolationGate) wiresIntermediateEval(i uint64) Range {
	if i >= g.numIntermediates() {
		panic("Invalid intermediate index")
	}
	start := g.startIntermediates() + D*i
	return Range{start, start + D}
}

// The wires corresponding to the i'th intermediate product.
func (g *CosetInterpolationGate) wiresIntermediateProd(i uint64) Range {
	if i >= g.numIntermediates() {
		panic("Invalid intermediate index")
	}
	start := g.startIntermediates() + D*(g.numIntermediates()+i)
	return Range{start, start + D}
}

// End of wire indices, exclusive.
func (g *CosetInterpolationGate) end() uint64 {
	return g.startIntermediates() + D*(2*g.numIntermediates()+1)
}

// Wire indices of the shifted point to evaluate the interpolant at.
func (g *CosetInterpolationGate) wiresShiftedEvaluationPoint() Range {
	start := g.startIntermediates() + D*2*g.numIntermediates()
	return Range{start, start + D}
}

func (g *CosetInterpolationGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}
	return constraints
}
