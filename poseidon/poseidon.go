package poseidon

import (
	. "gnark-ed25519/field"

	"github.com/consensys/gnark/frontend"
)

const HALF_N_FULL_ROUNDS = 4
const N_FULL_ROUNDS_TOTAL = 2 * HALF_N_FULL_ROUNDS
const N_PARTIAL_ROUNDS = 22
const N_ROUNDS = N_FULL_ROUNDS_TOTAL + N_PARTIAL_ROUNDS
const MAX_WIDTH = 12
const WIDTH = 12
const SPONGE_WIDTH = 12
const SPONGE_RATE = 8

type PoseidonState = [WIDTH]F
type PoseidonChip struct {
	api   frontend.API `gnark:"-"`
	field frontend.API `gnark:"-"`
}

func NewPoseidonChip(api frontend.API, field frontend.API) *PoseidonChip {
	return &PoseidonChip{api: api, field: field}
}

func (c *PoseidonChip) Poseidon(input PoseidonState) PoseidonState {
	state := input
	roundCounter := 0
	state = c.fullRounds(state, &roundCounter)
	state = c.partialRounds(state, &roundCounter)
	state = c.fullRounds(state, &roundCounter)
	return state
}

func (c *PoseidonChip) HashNToMNoPad(input []F, nbOutputs int) []F {
	var state PoseidonState

	for i := 0; i < WIDTH; i++ {
		state[i] = ZERO_F
	}

	for i := 0; i < len(input); i += SPONGE_RATE {
		for j := 0; j < SPONGE_RATE; j++ {
			if i+j < len(input) {
				state[j] = input[i+j]
			}
		}
		state = c.Poseidon(state)
	}

	var outputs []F

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

func (c *PoseidonChip) HashNoPad(input []F) Hash {
	var hash Hash
	copy(hash[:], c.HashNToMNoPad(input, 4))
	return hash
}

func (c *PoseidonChip) fullRounds(state PoseidonState, roundCounter *int) PoseidonState {
	for i := 0; i < HALF_N_FULL_ROUNDS; i++ {
		state = c.constantLayer(state, roundCounter)
		state = c.sBoxLayer(state)
		state = c.mdsLayer(state)
		*roundCounter += 1
	}
	return state
}

func (c *PoseidonChip) partialRounds(state PoseidonState, roundCounter *int) PoseidonState {
	state = c.partialFirstConstantLayer(state)
	state = c.mdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		state[0] = c.sBoxMonomial(state[0])
		state[0] = c.field.Add(state[0], FAST_PARTIAL_ROUND_CONSTANTS[i]).(F)
		state = c.mdsPartialLayerFast(state, i)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *PoseidonChip) constantLayer(state PoseidonState, roundCounter *int) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < WIDTH {
			roundConstant := NewFieldElement(ALL_ROUND_CONSTANTS[i+WIDTH*(*roundCounter)])
			state[i] = c.field.Add(state[i], roundConstant).(F)
		}
	}
	return state
}

func (c *PoseidonChip) sBoxLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < WIDTH {
			state[i] = c.sBoxMonomial(state[i])
		}
	}
	return state
}

func (c *PoseidonChip) sBoxMonomial(x F) F {
	x2 := c.field.Mul(x, x)
	x4 := c.field.Mul(x2, x2)
	x3 := c.field.Mul(x2, x)
	return c.field.Mul(x3, x4).(F)
}

func (c *PoseidonChip) mdsRowShf(r int, v [WIDTH]frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)

	for i := 0; i < 12; i++ {
		if i < WIDTH {
			res1 := c.api.Mul(v[(i+r)%WIDTH], frontend.Variable(MDS_MATRIX_CIRC[i]))
			res = c.api.Add(res, res1)
		}
	}

	res = c.api.Add(res, c.api.Mul(v[r], MDS_MATRIX_DIAG[r]))
	return res
}

func (c *PoseidonChip) mdsLayer(state_ PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < WIDTH; i++ {
		result[i] = NewFieldElement(0)
	}

	var state [WIDTH]frontend.Variable
	for i := 0; i < WIDTH; i++ {
		state[i] = c.api.FromBinary(c.field.ToBinary(state_[i])...)
	}

	for r := 0; r < 12; r++ {
		if r < WIDTH {
			sum := c.mdsRowShf(r, state)
			bits := c.api.ToBinary(sum)
			result[r] = c.field.FromBinary(bits).(F)
		}
	}

	return result
}

func (c *PoseidonChip) partialFirstConstantLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < WIDTH {
			state[i] = c.field.Add(state[i], NewFieldElement(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i])).(F)
		}
	}
	return state
}

func (c *PoseidonChip) mdsPartialLayerInit(state PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < 12; i++ {
		result[i] = NewFieldElement(0)
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < WIDTH {
			for d := 1; d < 12; d++ {
				if d < WIDTH {
					t := NewFieldElement(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1])
					result[d] = c.field.Add(result[d], c.field.Mul(state[r], t)).(F)
				}
			}
		}
	}

	return result
}

func (c *PoseidonChip) mdsPartialLayerFast(state PoseidonState, r int) PoseidonState {
	dSum := frontend.Variable(0)
	for i := 1; i < 12; i++ {
		if i < WIDTH {
			t := frontend.Variable(FAST_PARTIAL_ROUND_W_HATS[r][i-1])
			si := c.api.FromBinary(c.field.ToBinary(state[i])...)
			dSum = c.api.Add(dSum, c.api.Mul(si, t))
		}
	}

	s0 := c.api.FromBinary(c.field.ToBinary(state[0])...)
	mds0to0 := frontend.Variable(MDS_MATRIX_CIRC[0] + MDS_MATRIX_DIAG[0])
	dSum = c.api.Add(dSum, c.api.Mul(s0, mds0to0))
	d := c.field.FromBinary(c.api.ToBinary(dSum))

	var result PoseidonState
	for i := 0; i < WIDTH; i++ {
		result[i] = NewFieldElement(0)
	}

	result[0] = d.(F)

	for i := 1; i < 12; i++ {
		if i < WIDTH {
			t := NewFieldElement(FAST_PARTIAL_ROUND_VS[r][i-1])
			result[i] = c.field.Add(state[i], c.field.Mul(state[0], t)).(F)
		}
	}

	return result
}
