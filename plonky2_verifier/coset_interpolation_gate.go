package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	"regexp"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/field/goldilocks"
)

var cosetInterpolationGateRegex = regexp.MustCompile("CosetInterpolationGate { subgroup_bits: (?P<subgroupBits>[0-9]+), degree: (?P<degree>[0-9]+), barycentric_weights: \\[(?P<barycentricWeights>[0-9, ]+)\\], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>")

func deserializeCosetInterpolationGate(parameters map[string]string) gate {
	// Has the format CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 18446744069414584577, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 18446744069415632897, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
	subgroupBits, hasSubgroupBits := parameters["subgroupBits"]
	degree, hasDegree := parameters["degree"]
	barycentricWeights, hasBarycentricWeights := parameters["barycentricWeights"]

	if !hasSubgroupBits || !hasDegree || !hasBarycentricWeights {
		panic("missing subgroupBits, degree or barycentricWeights in CosetInterpolationGate")
	}

	subgroupBitsInt, err := strconv.ParseUint(subgroupBits, 10, 64)
	if err != nil {
		panic("invalid subgroupBits in CosetInterpolationGate")
	}

	degreeInt, err := strconv.ParseUint(degree, 10, 64)
	if err != nil {
		panic("invalid degree in CosetInterpolationGate")
	}

	barycentricWeightsStr := strings.Split(barycentricWeights, ",")
	barycentricWeightsInt := make([]goldilocks.Element, len(barycentricWeightsStr))
	for i, barycentricWeightStr := range barycentricWeightsStr {
		barycentricWeightStr = strings.TrimSpace(barycentricWeightStr)
		barycentricWeightInt, err := strconv.ParseUint(barycentricWeightStr, 10, 64)
		if err != nil {
			panic("invalid barycentricWeights in CosetInterpolationGate")
		}
		barycentricWeightsInt[i].SetUint64(barycentricWeightInt)
	}

	return NewCosetInterpolationGate(subgroupBitsInt, degreeInt, barycentricWeightsInt)
}

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

// Wire indices of the shifted point to evaluate the interpolant at.
func (g *CosetInterpolationGate) wiresShiftedEvaluationPoint() Range {
	start := g.startIntermediates() + D*2*g.numIntermediates()
	return Range{start, start + D}
}

func (g *CosetInterpolationGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}

	shift := vars.localWires[g.wireShift()]
	evaluationPoint := vars.GetLocalExtAlgebra(g.wiresEvaluationPoint())
	shiftedEvaluationPoint := vars.GetLocalExtAlgebra(g.wiresShiftedEvaluationPoint())

	negShift := p.qeAPI.ScalarMulExtension(shift, NEG_ONE_F)

	tmp := p.qeAPI.ScalarMulExtensionAlgebra(negShift, shiftedEvaluationPoint)
	tmp = p.qeAPI.AddExtensionAlgebra(tmp, evaluationPoint)

	for i := 0; i < D; i++ {
		constraints = append(constraints, tmp[i])
	}

	domain := TwoAdicSubgroup(g.subgroupBits)
	values := []QEAlgebra{}
	for i := uint64(0); i < g.numPoints(); i++ {
		values = append(values, vars.GetLocalExtAlgebra(g.wiresValue(i)))
	}
	weights := g.barycentricWeights

	initialEval := p.qeAPI.ZERO_QE_ALGEBRA
	initialProd := QEAlgebra{p.qeAPI.ONE_QE, p.qeAPI.ZERO_QE}
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
		for j := 0; j < D; j++ {
			constraints = append(constraints, evalDiff[j])
		}

		prodDiff := p.qeAPI.SubExtensionAlgebra(intermediateProd, computedProd)
		for j := 0; j < D; j++ {
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
	for j := 0; j < D; j++ {
		constraints = append(constraints, evalDiff[j])
	}

	return constraints
}
