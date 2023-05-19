package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"
)

const (
	WIRE_SUM    = 0
	START_LIMBS = 1
)

type BaseSumGate struct {
	numLimbs uint64
	base     uint64
}

func NewBaseSumGate(numLimbs uint64, base uint64) *BaseSumGate {
	return &BaseSumGate{
		numLimbs: numLimbs,
		base:     base,
	}
}

func (g *BaseSumGate) Id() string {
	return fmt.Sprintf("BaseSumGate { num_ops: %d } + Base: %d", g.numLimbs, g.base)
}

func (g *BaseSumGate) limbs() []uint64 {
	limbIndices := make([]uint64, g.numLimbs)
	for i := uint64(0); i < g.numLimbs; i++ {
		limbIndices[i] = uint64(START_LIMBS + i)
	}

	return limbIndices
}

func (g *BaseSumGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []field.QuadraticExtension {
	sum := vars.localWires[WIRE_SUM]
	limbs := make([]field.QuadraticExtension, g.numLimbs)
	limbIndices := g.limbs()
	for i, limbIdx := range limbIndices {
		limbs[i] = vars.localWires[limbIdx]
	}

	base_qe := p.qeAPI.FieldToQE(field.NewFieldElement(g.base))
	computedSum := p.qeAPI.ReduceWithPowers(
		limbs,
		base_qe,
	)

	var constraints []field.QuadraticExtension
	constraints = append(constraints, p.qeAPI.SubExtension(computedSum, sum))
	for _, limb := range limbs {
		acc := p.qeAPI.ONE_QE
		for i := uint64(0); i < g.base; i++ {
			difference := p.qeAPI.SubExtension(limb, p.qeAPI.FieldToQE(field.NewFieldElement(i)))
			acc = p.qeAPI.MulExtension(acc, difference)
		}
		constraints = append(constraints, acc)
	}

	return constraints
}
