package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"
)

func (g *PoseidonGate) WireInput(i uint64) uint64 {
	return i
}

func (g *PoseidonGate) WireOutput(i uint64) uint64 {
	return poseidon.SPONGE_WIDTH + i
}

func (g *PoseidonGate) WireSwap() uint64 {
	return 2 * poseidon.SPONGE_WIDTH
}

const START_DELTA = 2*poseidon.SPONGE_WIDTH + 1

func (g *PoseidonGate) WireDelta(i uint64) uint64 {
	if i >= 4 {
		panic("Delta index out of range")
	}
	return START_DELTA + i
}

const START_FULL_0 = START_DELTA + 4

func (g *PoseidonGate) WireFullSBox0(round uint64, i uint64) uint64 {
	if round == 0 {
		panic("First-round S-box inputs are not stored as wires")
	}
	if round >= poseidon.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return START_FULL_0 + (round-1)*poseidon.SPONGE_WIDTH + i
}

const START_PARTIAL = START_FULL_0 + (poseidon.HALF_N_FULL_ROUNDS-1)*poseidon.SPONGE_WIDTH

func (g *PoseidonGate) WirePartialSBox(round uint64) uint64 {
	if round >= poseidon.N_PARTIAL_ROUNDS {
		panic("S-box input round out of range")
	}
	return START_PARTIAL + round
}

const START_FULL_1 = START_PARTIAL + poseidon.N_PARTIAL_ROUNDS

func (g *PoseidonGate) WireFullSBox1(round uint64, i uint64) uint64 {
	if round >= poseidon.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return START_FULL_1 + round*poseidon.SPONGE_WIDTH + i
}

func (g *PoseidonGate) WiresEnd() uint64 {
	return START_FULL_1 + poseidon.HALF_N_FULL_ROUNDS*poseidon.SPONGE_WIDTH
}

type PoseidonGate struct {
}

func (p *PoseidonGate) EvalUnfiltered(pc *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	constraints := []QuadraticExtension{}

	// Assert that `swap` is binary.
	swap := vars.localWires[p.WireSwap()]
	notSwap := pc.qeAPI.SubExtension(pc.qeAPI.FieldToQE(ONE_F), swap)
	constraints = append(constraints, pc.qeAPI.MulExtension(swap, notSwap))

	// Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
	for i := uint64(0); i < 4; i++ {
		inputLhs := vars.localWires[p.WireInput(i)]
		inputRhs := vars.localWires[p.WireInput(i+4)]
		deltaI := vars.localWires[p.WireDelta(i)]
		diff := pc.qeAPI.SubExtension(inputRhs, inputLhs)
		expectedDeltaI := pc.qeAPI.MulExtension(swap, diff)
		constraints = append(constraints, pc.qeAPI.SubExtension(expectedDeltaI, deltaI))
	}

	// Compute the possibly-swapped input layer.
	state := make([]QuadraticExtension, poseidon.SPONGE_WIDTH)
	for i := uint64(0); i < 4; i++ {
		deltaI := vars.localWires[p.WireDelta(i)]
		inputLhs := vars.localWires[p.WireInput(i)]
		inputRhs := vars.localWires[p.WireInput(i+4)]
		state[i] = pc.qeAPI.AddExtension(inputLhs, deltaI)
		state[i+4] = pc.qeAPI.SubExtension(inputRhs, deltaI)
	}
	for i := uint64(8); i < poseidon.SPONGE_WIDTH; i++ {
		state[i] = vars.localWires[p.WireInput(i)]
	}

	round_ctr := 0

	// First set of full rounds.
	for r := uint64(0); r < poseidon.HALF_N_FULL_ROUNDS; r++ {
		// TODO: constantLayerField(state, round_ctr)
		if r != 0 {
			for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
				sBoxIn := vars.localWires[p.WireFullSBox0(r, i)]
				constraints = append(constraints, pc.qeAPI.SubExtension(state[i], sBoxIn))
				state[i] = sBoxIn
			}
		}
		// TODO: sboxLayerField(state)
		// TODO: state = mdsLayerField(state)
		round_ctr++
	}

	// Partial rounds.
	// TODO: partialFirstConstantLayer(state)
	// TODO: state = mdsParitalLayerInit(state)
	for r := uint64(0); r < poseidon.N_PARTIAL_ROUNDS-1; r++ {
		sBoxIn := vars.localWires[p.WirePartialSBox(r)]
		constraints = append(constraints, pc.qeAPI.SubExtension(state[0], sBoxIn))
		// TODO: state[0] = sBoxMonomial(sBoxIn)
		// TODO: state[0] += NewFieldElement(FAST_PARTIAL_ROUND_CONSTANTS[r])
		// TODO: state = mdsParitalLayerFastField(state, r)
	}
	sBoxIn := vars.localWires[p.WirePartialSBox(poseidon.N_PARTIAL_ROUNDS-1)]
	constraints = append(constraints, pc.qeAPI.SubExtension(state[0], sBoxIn))
	// TODO: state[0] = sBoxMonomial(sBoxIn)
	// TODO: state = mdsPartialLayerLastField(state, poseidon.N_PARTIAL_ROUNDS - 1)
	round_ctr += poseidon.N_PARTIAL_ROUNDS

	// Second set of full rounds.
	for r := uint64(0); r < poseidon.HALF_N_FULL_ROUNDS; r++ {
		// TODO: constantLayerField(state, round_ctr)
		for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
			sBoxIn := vars.localWires[p.WireFullSBox1(r, i)]
			constraints = append(constraints, pc.qeAPI.SubExtension(state[i], sBoxIn))
			state[i] = sBoxIn
		}
		// TODO: sboxLayerField(state)
		// TODO: state = mdsLayerField(state)
		round_ctr++
	}

	for i := uint64(0); i < poseidon.SPONGE_WIDTH; i++ {
		constraints = append(constraints, pc.qeAPI.SubExtension(state[i], vars.localWires[p.WireOutput(i)]))
	}

	return constraints
}
