package poseidon

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const HALF_N_FULL_ROUNDS_BN128 = 4
const N_FULL_ROUNDS_TOTAL_BN128 = 2 * HALF_N_FULL_ROUNDS
const N_PARTIAL_ROUNDS_BN128 = 56
const N_ROUNDS_BN128 = N_FULL_ROUNDS_TOTAL + N_PARTIAL_ROUNDS
const SPONGE_WIDTH_BN128 = 4
const SPONGE_RATE_BN128 = 3

type PoseidonBN128Chip struct {
	api frontend.API `gnark:"-"`
}

type PoseidonBN128State = [SPONGE_WIDTH_BN128]frontend.Variable

type BN128Hash = frontend.Variable

func NewPoseidonBN128Chip(api frontend.API) *PoseidonBN128Chip {
	return &PoseidonBN128Chip{api: api}
}

func (c *PoseidonBN128Chip) Poseidon(state PoseidonBN128State) PoseidonBN128State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *PoseidonBN128Chip) HashNToMNoPad(input []frontend.Variable, nbOutputs int) []frontend.Variable {
	var inputs PoseidonBN128State
	var state PoseidonBN128State

	inputs[0] = frontend.Variable(0)
	for i := 0; i < len(input); i += SPONGE_RATE_BN128 {
		for j := 0; j < SPONGE_RATE_BN128; j++ {
			if i+j < len(input) {
				inputs[j+1] = input[i+j]
			}
		}
		state = c.Poseidon(inputs)
		inputs[0] = state[0]
	}

	var outputs []frontend.Variable

	for {
		for i := 0; i < SPONGE_RATE_BN128; i++ {
			outputs = append(outputs, state[i])
			if len(outputs) == nbOutputs {
				return outputs
			}
		}
		state = c.Poseidon(state)
	}
}

func (c *PoseidonBN128Chip) HashNoPad(input []frontend.Variable) BN128Hash {
	hash := c.HashNToMNoPad(input, 1)[0]
	return hash
}

func (c *PoseidonBN128Chip) fullRounds(state PoseidonBN128State, isFirst bool) PoseidonBN128State {
	for i := 0; i < N_FULL_ROUNDS_TOTAL_BN128/2-1; i++ {
		state = c.exp5state(state)
		if isFirst {
			state = c.ark(state, (i+1)*SPONGE_WIDTH_BN128)
		} else {
			state = c.ark(state, (N_FULL_ROUNDS_TOTAL_BN128/2+1)*SPONGE_WIDTH_BN128+N_PARTIAL_ROUNDS_BN128+i*SPONGE_WIDTH_BN128)
		}
		state = c.mix(state, mMatrix)
	}

	state = c.exp5state(state)
	if isFirst {
		state = c.ark(state, (N_FULL_ROUNDS_TOTAL_BN128/2)*SPONGE_WIDTH_BN128)
		state = c.mix(state, pMatrix)
	} else {
		state = c.mix(state, mMatrix)
	}

	return state
}

func (c *PoseidonBN128Chip) partialRounds(state PoseidonBN128State) PoseidonBN128State {
	for i := 0; i < N_PARTIAL_ROUNDS_BN128; i++ {
		state[0] = c.exp5(state[0])
		state[0] = c.api.Add(state[0], cConstants[(N_FULL_ROUNDS_TOTAL_BN128/2+1)*SPONGE_WIDTH_BN128+i])

		var mul frontend.Variable
		newState0 := frontend.Variable(0)
		for j := 0; j < SPONGE_WIDTH_BN128; j++ {
			mul = c.api.Mul(sConstants[(SPONGE_WIDTH_BN128*2-1)*i+j], state[j])
			newState0 = c.api.Add(newState0, mul)
		}

		for k := 1; k < SPONGE_WIDTH_BN128; k++ {
			mul = c.api.Mul(state[0], sConstants[(SPONGE_WIDTH_BN128*2-1)*i+SPONGE_WIDTH_BN128+k-1])
			state[k] = c.api.Add(state[k], mul)
		}
		state[0] = newState0
	}

	return state
}

func (c *PoseidonBN128Chip) ark(state PoseidonBN128State, it int) PoseidonBN128State {
	var result PoseidonBN128State

	for i := 0; i < len(state); i++ {
		result[i] = c.api.Add(state[i], cConstants[it+i])
	}

	return result
}

func (c *PoseidonBN128Chip) exp5(x frontend.Variable) frontend.Variable {
	x2 := c.api.Mul(x, x)
	x4 := c.api.Mul(x2, x2)
	return c.api.Mul(x4, x)
}

func (c *PoseidonBN128Chip) exp5state(state PoseidonBN128State) PoseidonBN128State {
	for i := 0; i < SPONGE_WIDTH_BN128; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *PoseidonBN128Chip) mix(state_ PoseidonBN128State, constantMatrix [][]*big.Int) PoseidonBN128State {
	var mul frontend.Variable
	var result PoseidonBN128State

	for i := 0; i < SPONGE_WIDTH_BN128; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < SPONGE_WIDTH_BN128; i++ {
		for j := 0; j < SPONGE_WIDTH_BN128; j++ {
			mul = c.api.Mul(constantMatrix[j][i], state_[j])
			result[i] = c.api.Add(result[i], mul)
		}
	}

	return result
}
