package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var mulExtensionGateRegex = regexp.MustCompile("MulExtensionGate { num_ops: (?P<numOps>[0-9]+) }")

func deserializeMulExtensionGate(parameters map[string]string) Gate {
	// Has the format "MulExtensionGate { num_ops: 13 }"
	numOps, hasNumOps := parameters["numOps"]
	if !hasNumOps {
		panic("Missing field num_ops in MulExtensionGate")
	}

	numOpsInt, err := strconv.Atoi(numOps)
	if err != nil {
		panic("Invalid num_ops field in MulExtensionGate")
	}

	return NewMultiplicationExtensionGate(uint64(numOpsInt))
}

type MultiplicationExtensionGate struct {
	numOps uint64
}

func NewMultiplicationExtensionGate(numOps uint64) *MultiplicationExtensionGate {
	return &MultiplicationExtensionGate{
		numOps: numOps,
	}
}

func (g *MultiplicationExtensionGate) Id() string {
	return fmt.Sprintf("ArithmeticExtensionGate { num_ops: %d }", g.numOps)
}

func (g *MultiplicationExtensionGate) wiresIthMultiplicand0(i uint64) Range {
	return Range{3 * field.D * i, 3*field.D*i + field.D}
}

func (g *MultiplicationExtensionGate) wiresIthMultiplicand1(i uint64) Range {
	return Range{3*field.D*i + field.D, 3*field.D*i + 2*field.D}
}

func (g *MultiplicationExtensionGate) wiresIthOutput(i uint64) Range {
	return Range{3*field.D*i + 2*field.D, 3*field.D*i + 3*field.D}
}

func (g *MultiplicationExtensionGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	const0 := vars.localConstants[0]

	constraints := []field.QuadraticExtension{}
	for i := uint64(0); i < g.numOps; i++ {
		multiplicand0 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand0(i))
		multiplicand1 := vars.GetLocalExtAlgebra(g.wiresIthMultiplicand1(i))
		output := vars.GetLocalExtAlgebra(g.wiresIthOutput(i))

		mul := qeAPI.MulExtensionAlgebra(multiplicand0, multiplicand1)
		computed_output := qeAPI.ScalarMulExtensionAlgebra(const0, mul)

		diff := qeAPI.SubExtensionAlgebra(output, computed_output)
		for j := 0; j < field.D; j++ {
			constraints = append(constraints, diff[j])
		}
	}

	return constraints
}
