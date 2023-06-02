package poseidon

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

const HALF_N_FULL_ROUNDS = 4
const N_FULL_ROUNDS_TOTAL = 2 * HALF_N_FULL_ROUNDS
const N_PARTIAL_ROUNDS = 22
const N_ROUNDS = N_FULL_ROUNDS_TOTAL + N_PARTIAL_ROUNDS
const MAX_WIDTH = 12
const SPONGE_WIDTH = 12
const SPONGE_RATE = 8

type PoseidonChip struct {
	api frontend.API `gnark:"-"`
}

// All entries in state should be within the goldilocks field
type PoseidonState = [SPONGE_WIDTH]frontend.Variable

type NewHash = [4]frontend.Variable

func NewPoseidonChip(api frontend.API) *PoseidonChip {
	return &PoseidonChip{api: api}
}

func (c *PoseidonChip) Poseidon(input PoseidonState) PoseidonState {
	state := input
	roundCounter := 0
	state = c.FullRounds(state, &roundCounter)
	state = c.PartialRounds(state, &roundCounter)
	state = c.FullRounds(state, &roundCounter)
	return state
}

func (c *PoseidonChip) HashNToMNoPad(input []frontend.Variable, nbOutputs int) []frontend.Variable {
	var state PoseidonState

	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = field.ZERO_VAR
	}

	for i := 0; i < len(input); i += SPONGE_RATE {
		for j := 0; j < SPONGE_RATE; j++ {
			if i+j < len(input) {
				state[j] = input[i+j]
			}
		}
		state = c.Poseidon(state)
	}

	var outputs []frontend.Variable

	for {
		for i := 0; i < SPONGE_RATE; i++ {
			outputs = append(outputs, state[i])
			if len(outputs) == nbOutputs {
				return outputs
			}
		}
		state = c.Poseidon(state)
	}
}

func (c *PoseidonChip) HashNoPad(input []frontend.Variable) NewHash {
	var hash NewHash
	copy(hash[:], c.HashNToMNoPad(input, 4))
	return hash
}

func (c *PoseidonChip) FullRounds(state PoseidonState, roundCounter *int) PoseidonState {
	for i := 0; i < HALF_N_FULL_ROUNDS; i++ {
		state = c.ConstantLayer(state, roundCounter)
		state = c.SBoxLayer(state)
		state = c.MdsLayer(state)
		*roundCounter += 1
	}
	return state
}

func (c *PoseidonChip) PartialRounds(state PoseidonState, roundCounter *int) PoseidonState {
	state = c.PartialFirstConstantLayer(state)
	state = c.MdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		state[0] = c.SBoxMonomial(state[0])
		state[0] = field.GoldilocksMulAdd(c.api, state[0], field.ONE_VAR, FAST_PARTIAL_ROUND_CONSTANTS[i].Limbs[0])
		state = c.MdsPartialLayerFast(state, i)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *PoseidonChip) ConstantLayer(state PoseidonState, roundCounter *int) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)]
			state[i] = field.GoldilocksMulAdd(c.api, state[i], field.ONE_VAR, roundConstant.Limbs[0])
		}
	}
	return state
}

// Can assume that X is in the field
func (c *PoseidonChip) SBoxMonomial(x frontend.Variable) frontend.Variable {
	x2 := field.GoldilocksMulAdd(c.api, x, x, field.ZERO_VAR)
	x4 := field.GoldilocksMulAdd(c.api, x2, x2, field.ZERO_VAR)
	x3 := field.GoldilocksMulAdd(c.api, x, x2, field.ZERO_VAR)
	return field.GoldilocksMulAdd(c.api, x3, x4, field.ZERO_VAR)
}

func (c *PoseidonChip) SBoxLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.SBoxMonomial(state[i])
		}
	}
	return state
}

func (c *PoseidonChip) MdsRowShf(r int, v [SPONGE_WIDTH]frontend.Variable) frontend.Variable {
	res := field.ZERO_VAR

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			res1 := c.api.Mul(v[(i+r)%SPONGE_WIDTH], MDS_MATRIX_CIRC_VARS[i])
			res = c.api.Add(res, res1)
		}
	}

	res = c.api.Add(res, c.api.Mul(v[r], MDS_MATRIX_DIAG_VARS[r]))
	return res
}

func (c *PoseidonChip) MdsLayer(state_ PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = field.ZERO_VAR
	}

	var state [SPONGE_WIDTH]frontend.Variable
	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = state_[i]
	}

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			sum := c.MdsRowShf(r, state)
			result[r] = field.GoldilocksReduce(c.api, sum)
		}
	}

	return result
}

func (c *PoseidonChip) PartialFirstConstantLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = field.GoldilocksMulAdd(c.api, state[i], field.ONE_VAR, FAST_PARTIAL_FIRST_ROUND_CONSTANT[i].Limbs[0])
		}
	}
	return state
}

func (c *PoseidonChip) MdsPartialLayerInit(state PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < 12; i++ {
		result[i] = field.ZERO_VAR
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < SPONGE_WIDTH {
			for d := 1; d < 12; d++ {
				if d < SPONGE_WIDTH {
					t := FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1].Limbs[0]
					result[d] = field.GoldilocksMulAdd(c.api, state[r], t, result[d])
				}
			}
		}
	}

	return result
}

func (c *PoseidonChip) MdsPartialLayerFast(state PoseidonState, r int) PoseidonState {
	dSum := field.ZERO_VAR
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_W_HATS_VARS[r][i-1]
			si := state[i]
			dSum = c.api.Add(dSum, c.api.Mul(si, t))
		}
	}

	s0 := state[0]
	dSum = c.api.Add(dSum, c.api.Mul(s0, MDS0TO0_VAR))
	d := field.GoldilocksReduce(c.api, dSum)

	var result PoseidonState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = field.ZERO_VAR
	}

	result[0] = d

	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_VS[r][i-1].Limbs[0]
			result[i] = field.GoldilocksMulAdd(c.api, state[0], t, state[i])
		}
	}

	return result
}
