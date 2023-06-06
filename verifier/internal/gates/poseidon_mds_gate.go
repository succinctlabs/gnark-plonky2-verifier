package gates

import (
	"regexp"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var poseidonMdsGateRegex = regexp.MustCompile("PoseidonMdsGate.*")

func deserializePoseidonMdsGate(parameters map[string]string) Gate {
	// Has the format "PoseidonMdsGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>"
	return NewPoseidonMdsGate()
}

type PoseidonMdsGate struct {
}

func NewPoseidonMdsGate() *PoseidonMdsGate {
	return &PoseidonMdsGate{}
}

func (g *PoseidonMdsGate) Id() string {
	return "PoseidonMdsGate"
}

func (g *PoseidonMdsGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	return []field.QuadraticExtension{}
}
