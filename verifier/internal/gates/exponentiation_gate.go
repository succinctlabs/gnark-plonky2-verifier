package gates

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

var exponentiationGateRegex = regexp.MustCompile("ExponentiationGate { num_power_bits: (?P<numPowerBits>[0-9]+), _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=(?P<base>[0-9]+)>")

func deserializeExponentiationGate(parameters map[string]string) Gate {
	// Has the format "ExponentiationGate { num_power_bits: 67, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"
	numPowerBits, hasNumPowerBits := parameters["numPowerBits"]
	if !hasNumPowerBits {
		panic("Missing field num_power_bits in ExponentiationGate")
	}

	numPowerBitsInt, err := strconv.Atoi(numPowerBits)
	if err != nil {
		panic("Invalid num_power_bits field in ExponentiationGate")
	}

	return NewExponentiationGate(uint64(numPowerBitsInt))
}

type ExponentiationGate struct {
	numPowerBits uint64
}

func NewExponentiationGate(numPowerBits uint64) *ExponentiationGate {
	return &ExponentiationGate{
		numPowerBits: numPowerBits,
	}
}

func (g *ExponentiationGate) Id() string {
	return fmt.Sprintf("ExponentiationGate { num_power_bits: %d }", g.numPowerBits)
}

func (g *ExponentiationGate) wireBase() uint64 {
	return 0
}

// / The `i`th bit of the exponent, in little-endian order.
func (g *ExponentiationGate) wirePowerBit(i uint64) uint64 {
	if i >= g.numPowerBits {
		panic("Invalid power bit index")
	}
	return 1 + i
}

func (g *ExponentiationGate) wireOutput() uint64 {
	return 1 + g.numPowerBits
}

func (g *ExponentiationGate) wireIntermediateValue(i uint64) uint64 {
	if i >= g.numPowerBits {
		panic("Invalid intermediate value index")
	}
	return 2 + g.numPowerBits + i
}

func (g *ExponentiationGate) EvalUnfiltered(api frontend.API, qeAPI *field.QuadraticExtensionAPI, vars EvaluationVars) []field.QuadraticExtension {
	base := vars.localWires[g.wireBase()]

	var powerBits []field.QuadraticExtension
	for i := uint64(0); i < g.numPowerBits; i++ {
		powerBits = append(powerBits, vars.localWires[g.wirePowerBit(i)])
	}

	var intermediateValues []field.QuadraticExtension
	for i := uint64(0); i < g.numPowerBits; i++ {
		intermediateValues = append(intermediateValues, vars.localWires[g.wireIntermediateValue(i)])
	}

	output := vars.localWires[g.wireOutput()]

	var constraints []field.QuadraticExtension

	for i := uint64(0); i < g.numPowerBits; i++ {
		var prevIntermediateValue field.QuadraticExtension
		if i == 0 {
			prevIntermediateValue = qeAPI.ONE_QE
		} else {
			prevIntermediateValue = qeAPI.SquareExtension(intermediateValues[i-1])
		}

		// powerBits is in LE order, but we accumulate in BE order.
		curBit := powerBits[g.numPowerBits-i-1]

		// Do a polynomial representation of generaized select (where the selector variable doesn't have to be binary)
		// if b { x } else { y }
		// i.e. `bx - (by-y)`.
		tmp := qeAPI.MulExtension(curBit, qeAPI.ONE_QE)
		tmp = qeAPI.SubExtension(tmp, qeAPI.ONE_QE)
		mulBy := qeAPI.MulExtension(curBit, base)
		mulBy = qeAPI.SubExtension(mulBy, tmp)
		intermediateValueDiff := qeAPI.MulExtension(prevIntermediateValue, mulBy)
		intermediateValueDiff = qeAPI.SubExtension(intermediateValueDiff, intermediateValues[i])
		constraints = append(constraints, intermediateValueDiff)
	}

	outputDiff := qeAPI.SubExtension(output, intermediateValues[g.numPowerBits-1])
	constraints = append(constraints, outputDiff)

	return constraints
}
