package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var baseSumGateRegex = regexp.MustCompile(`BaseSumGate { num_limbs: (?P<numLimbs>[0-9]+) } \+ Base: (?P<base>[0-9]+)`)

func deserializeBaseSumGate(parameters map[string]string) Gate {

	// Has the format "BaseSumGate { num_limbs: 32 } + Base: 2"
	numLimbs, hasNumLimbs := parameters["numLimbs"]
	base, hasBase := parameters["base"]
	if !hasNumLimbs || !hasBase {
		panic("Missing field num_limbs or base in BaseSumGate")
	}

	numLimbsInt, err := strconv.Atoi(numLimbs)
	if err != nil {
		panic("Invalid num_limbs field in BaseSumGate")
	}

	baseInt, err := strconv.Atoi(base)
	if err != nil {
		panic("Invalid base field in BaseSumGate")
	}

	return NewBaseSumGate(uint64(numLimbsInt), uint64(baseInt))
}

const (
	BASESUM_GATE_WIRE_SUM    = 0
	BASESUM_GATE_START_LIMBS = 1
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
		limbIndices[i] = uint64(BASESUM_GATE_START_LIMBS + i)
	}

	return limbIndices
}

func (g *BaseSumGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	sum := vars.localWires[BASESUM_GATE_WIRE_SUM]
	limbs := make([]field.QuadraticExtension, g.numLimbs)
	limbIndices := g.limbs()
	for i, limbIdx := range limbIndices {
		limbs[i] = vars.localWires[limbIdx]
	}

	base_qe := qeAPI.FieldToQE(field.NewFieldConst(g.base))
	computedSum := qeAPI.ReduceWithPowers(
		limbs,
		base_qe,
	)

	var constraints []field.QuadraticExtension
	constraints = append(constraints, qeAPI.SubExtension(computedSum, sum))
	for _, limb := range limbs {
		acc := qeAPI.ONE_QE
		for i := uint64(0); i < g.base; i++ {
			difference := qeAPI.SubExtension(limb, qeAPI.FieldToQE(field.NewFieldConst(i)))
			acc = qeAPI.MulExtension(acc, difference)
		}
		constraints = append(constraints, acc)
	}

	return constraints
}
