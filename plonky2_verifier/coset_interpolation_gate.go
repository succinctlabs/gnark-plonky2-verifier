package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"

	"github.com/consensys/gnark-crypto/field/goldilocks"
)

type CosetInterpolationGate struct {
	subgroupBits       uint64
	degree             uint64
	barycentricWeights []goldilocks.Element
}

func NewCosetInterpolationGate(subgroupBits uint64, degree uint64, barycentricWeights []goldilocks.Element) *CosetInterpolationGate {
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
	start := g.startValues() + i*field.D
	return Range{start, start + field.D}
}

func (g *CosetInterpolationGate) startEvaluationPoint() uint64 {
	return g.startValues() + g.numPoints()*field.D
}

// Wire indices of the point to evaluate the interpolant at.
func (g *CosetInterpolationGate) wiresEvaluationPoint() Range {
	start := g.startEvaluationPoint()
	return Range{start, start + field.D}
}

func (g *CosetInterpolationGate) startEvaluationValue() uint64 {
	return g.startEvaluationPoint() + field.D
}

// Wire indices of the interpolated value.
func (g *CosetInterpolationGate) wiresEvaluationValue() Range {
	start := g.startEvaluationValue()
	return Range{start, start + field.D}
}

func (g *CosetInterpolationGate) startIntermediates() uint64 {
	return g.startEvaluationValue() + field.D
}

func (g *CosetInterpolationGate) numIntermediates() uint64 {
	return (g.numPoints() - 2) / (g.degree - 1)
}

// The wires corresponding to the i'th intermediate evaluation.
func (g *CosetInterpolationGate) wiresIntermediateEval(i uint64) Range {
	if i >= g.numIntermediates() {
		panic("Invalid intermediate index")
	}
	start := g.startIntermediates() + field.D*i
	return Range{start, start + field.D}
}

// The wires corresponding to the i'th intermediate product.
func (g *CosetInterpolationGate) wiresIntermediateProd(i uint64) Range {
	if i >= g.numIntermediates() {
		panic("Invalid intermediate index")
	}
	start := g.startIntermediates() + field.D*(g.numIntermediates()+i)
	return Range{start, start + field.D}
}

// Wire indices of the shifted point to evaluate the interpolant at.
func (g *CosetInterpolationGate) wiresShiftedEvaluationPoint() Range {
	start := g.startIntermediates() + field.D*2*g.numIntermediates()
	return Range{start, start + field.D}
}

func (g *CosetInterpolationGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	constraints := []field.QuadraticExtension{}

	shift := vars.localWires[g.wireShift()]
	evaluationPoint := vars.GetLocalExtAlgebra(g.wiresEvaluationPoint())
	shiftedEvaluationPoint := vars.GetLocalExtAlgebra(g.wiresShiftedEvaluationPoint())

	negShift := p.qeAPI.ScalarMulExtension(shift, field.NEG_ONE_F)

	tmp := p.qeAPI.ScalarMulExtensionAlgebra(negShift, shiftedEvaluationPoint)
	tmp = p.qeAPI.AddExtensionAlgebra(tmp, evaluationPoint)

	for i := 0; i < field.D; i++ {
		constraints = append(constraints, tmp[i])
	}

	domain := field.TwoAdicSubgroup(g.subgroupBits)
	values := []field.QEAlgebra{}
	for i := uint64(0); i < g.numPoints(); i++ {
		values = append(values, vars.GetLocalExtAlgebra(g.wiresValue(i)))
	}
	weights := g.barycentricWeights

	initialEval := p.qeAPI.ZERO_QE_ALGEBRA
	initialProd := field.QEAlgebra{p.qeAPI.ONE_QE, p.qeAPI.ZERO_QE}
	computedEval, computedProd := p.qeAPI.PartialInterpolateExtAlgebra(
		domain[:g.degree],
		values[:g.degree],
		weights[:g.degree],
		shiftedEvaluationPoint,
		initialEval,
		initialProd,
	)

	for i := uint64(0); i < g.numIntermediates(); i++ {
		intermediateEval := vars.GetLocalExtAlgebra(g.wiresIntermediateEval(i))
		intermediateProd := vars.GetLocalExtAlgebra(g.wiresIntermediateProd(i))

		evalDiff := p.qeAPI.SubExtensionAlgebra(intermediateEval, computedEval)
		for j := 0; j < field.D; j++ {
			constraints = append(constraints, evalDiff[j])
		}

		prodDiff := p.qeAPI.SubExtensionAlgebra(intermediateProd, computedProd)
		for j := 0; j < field.D; j++ {
			constraints = append(constraints, prodDiff[j])
		}

		startIndex := 1 + (g.degree-1)*(i+1)
		endIndex := startIndex + g.degree - 1
		computedEval, computedProd = p.qeAPI.PartialInterpolateExtAlgebra(
			domain[startIndex:endIndex],
			values[startIndex:endIndex],
			weights[startIndex:endIndex],
			shiftedEvaluationPoint,
			intermediateEval,
			intermediateProd,
		)
	}

	evaluationValue := vars.GetLocalExtAlgebra(g.wiresEvaluationValue())
	evalDiff := p.qeAPI.SubExtensionAlgebra(evaluationValue, computedEval)
	for j := 0; j < field.D; j++ {
		constraints = append(constraints, evalDiff[j])
	}

	return constraints
}
