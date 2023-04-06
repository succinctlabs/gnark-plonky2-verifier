package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

type ConstantGate struct {
	numConsts uint64
}

func NewConstantGate(numConsts uint64) *ConstantGate {
	return &ConstantGate{
		numConsts: numConsts,
	}
}

func (g *ConstantGate) Id() string {
	return fmt.Sprintf("ConstantGate { num_consts: %d }", g.numConsts)
}

func (g *ConstantGate) ConstInput(i uint64) uint64 {
	if i > g.numConsts {
		panic("Invalid constant index")
	}
	return i
}

func (g *ConstantGate) WireOutput(i uint64) uint64 {
	if i > g.numConsts {
		panic("Invalid wire index")
	}
	return i
}

func (g *ConstantGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}

	for i := uint64(0); i < g.numConsts; i++ {
		constraints = append(constraints, p.qeAPI.SubExtension(vars.localConstants[g.ConstInput(i)], vars.localWires[g.WireOutput(i)]))
	}

	return constraints
}
