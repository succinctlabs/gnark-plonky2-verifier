package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

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

func (g *ExponentiationGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	base := vars.localWires[g.wireBase()]

	var powerBits []QuadraticExtension
	for i := uint64(0); i < g.numPowerBits; i++ {
		powerBits = append(powerBits, vars.localWires[g.wirePowerBit(i)])
	}

	var intermediateValues []QuadraticExtension
	for i := uint64(0); i < g.numPowerBits; i++ {
		intermediateValues = append(intermediateValues, vars.localWires[g.wireIntermediateValue(i)])
	}

	output := vars.localWires[g.wireOutput()]

	var constraints []QuadraticExtension

	for i := uint64(0); i < g.numPowerBits; i++ {
		var prevIntermediateValue QuadraticExtension
		if i == 0 {
			prevIntermediateValue = p.qeAPI.ONE_QE
		} else {
			prevIntermediateValue = p.qeAPI.SquareExtension(intermediateValues[i-1])
		}

		// powerBits is in LE order, but we accumulate in BE order.
		curBit := powerBits[g.numPowerBits-i-1]

		// Do a polynomial representation of generaized select (where the selector variable doesn't have to be binary)
		// if b { x } else { y }
		// i.e. `bx - (by-y)`.
		tmp := p.qeAPI.MulExtension(curBit, p.qeAPI.ONE_QE)
		tmp = p.qeAPI.SubExtension(tmp, p.qeAPI.ONE_QE)
		mulBy := p.qeAPI.MulExtension(curBit, base)
		mulBy = p.qeAPI.SubExtension(mulBy, tmp)
		intermediateValueDiff := p.qeAPI.MulExtension(prevIntermediateValue, mulBy)
		intermediateValueDiff = p.qeAPI.SubExtension(intermediateValueDiff, intermediateValues[i])
		constraints = append(constraints, intermediateValueDiff)
	}

	outputDiff := p.qeAPI.SubExtension(output, intermediateValues[g.numPowerBits-1])
	constraints = append(constraints, outputDiff)

	return constraints
}
