package poseidon

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

const HALF_N_FULL_ROUNDS = 4
const N_PARTIAL_ROUNDS = 22
const MAX_WIDTH = 12
const SPONGE_WIDTH = 12
const SPONGE_RATE = 8

type PoseidonState = [SPONGE_WIDTH]frontend.Variable
type PoseidonStateExtension = [SPONGE_WIDTH]field.QuadraticExtension
type PoseidonHashOut = [4]field.F

type PoseidonChip struct {
	api      frontend.API                 `gnark:"-"`
	fieldAPI field.FieldAPI               `gnark:"-"`
	qeAPI    *field.QuadraticExtensionAPI `gnark:"-"`
}

func NewPoseidonChip(api frontend.API, fieldAPI field.FieldAPI, qeAPI *field.QuadraticExtensionAPI) *PoseidonChip {
	return &PoseidonChip{api: api, fieldAPI: fieldAPI, qeAPI: qeAPI}
}

// The permutation function.
// The input state MUST have all it's elements be within Goldilocks field (e.g. this function will not reduce the input elements).
// The returned state's elements will all be within Goldilocks field.
func (c *PoseidonChip) Poseidon(input PoseidonState) PoseidonState {
	state := input
	roundCounter := 0
	c.api.Println("Called Poseidon with input")
	c.OutputState(state)
	state = c.fullRounds(state, &roundCounter)
	c.api.Println("After first full rounds, state is")
	c.OutputState(state)
	state = c.partialRounds(state, &roundCounter)
	c.api.Println("After partial rounds, state is")
	c.OutputState(state)
	state = c.fullRounds(state, &roundCounter)
	c.api.Println("After second full round, state is")
	c.OutputState(state)
	return state
}

func (c *PoseidonChip) OutputState(state PoseidonState) {
	for i := 0; i < SPONGE_WIDTH; i++ {
		c.api.Println("State[", i, "] is: ", state[i])
	}
}

// The input elements MUST have all it's elements be within Goldilocks field.
// The returned slice's elements will all be within Goldilocks field.
func (c *PoseidonChip) HashNToMNoPad(input []frontend.Variable, nbOutputs int) []frontend.Variable {
	var state PoseidonState

	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = frontend.Variable(0)
	}
	c.api.Println("HashNToMNoPad state is")
	c.OutputState(state)

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

// The input elements can be outside of the Goldilocks field.
// The returned slice's elements will all be within Goldilocks field.
func (c *PoseidonChip) HashNoPad(input []field.F) PoseidonHashOut {
	var hash PoseidonHashOut
	inputVars := []frontend.Variable{}

	for i := 0; i < len(input); i++ {
		inputVars = append(inputVars, c.fieldAPI.Reduce(input[i]).Limbs[0])
	}

	c.api.Println("inputVars", inputVars)

	outputVars := c.HashNToMNoPad(inputVars, 4)

	c.api.Println("outputVars", outputVars)

	for i := 0; i < 4; i++ {
		hash[i] = c.fieldAPI.NewElement(outputVars[i])
	}

	return hash
}

func (c *PoseidonChip) ToVec(hash PoseidonHashOut) []field.F {
	return hash[:]
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
		state[0] = field.GoldilocksMulAdd(c.api, frontend.Variable(1), state[0], FAST_PARTIAL_ROUND_CONSTANTS[i])
		state = c.mdsPartialLayerFast(state, i)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *PoseidonChip) constantLayer(state PoseidonState, roundCounter *int) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)]
			state[i] = field.GoldilocksMulAdd(c.api, frontend.Variable(1), state[i], roundConstant)
		}
	}
	return state
}

func (c *PoseidonChip) ConstantLayerExtension(state PoseidonStateExtension, roundCounter *int) PoseidonStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := c.qeAPI.VarToQE(ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)])
			state[i] = c.qeAPI.AddExtension(state[i], roundConstant)
		}
	}
	return state
}

func (c *PoseidonChip) sBoxMonomial(x frontend.Variable) frontend.Variable {
	x2 := field.GoldilocksMulAdd(c.api, x, x, frontend.Variable(0))
	x4 := field.GoldilocksMulAdd(c.api, x2, x2, frontend.Variable(0))
	x6 := field.GoldilocksMulAdd(c.api, x4, x2, frontend.Variable(0))
	return field.GoldilocksMulAdd(c.api, x6, x, frontend.Variable(0))
}

func (c *PoseidonChip) SBoxMonomialExtension(x field.QuadraticExtension) field.QuadraticExtension {
	x2 := c.qeAPI.SquareExtension(x)
	x4 := c.qeAPI.SquareExtension(x2)
	x3 := c.qeAPI.MulExtension(x, x2)
	return c.qeAPI.MulExtension(x3, x4)
}

func (c *PoseidonChip) sBoxLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.sBoxMonomial(state[i])
		}
	}
	return state
}

func (c *PoseidonChip) SBoxLayerExtension(state PoseidonStateExtension) PoseidonStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.SBoxMonomialExtension(state[i])
		}
	}
	return state
}

func (c *PoseidonChip) mdsRowShf(r int, v [SPONGE_WIDTH]frontend.Variable) frontend.Variable {
	res := ZERO_VAR

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			res = field.GoldilocksMulAdd(c.api, v[(i+r)%SPONGE_WIDTH], MDS_MATRIX_CIRC_VARS[i], res)
		}
	}

	res = field.GoldilocksMulAdd(c.api, v[r], MDS_MATRIX_DIAG_VARS[r], res)
	return res
}

func (c *PoseidonChip) MdsRowShfExtension(r int, v [SPONGE_WIDTH]field.QuadraticExtension) field.QuadraticExtension {
	res := c.qeAPI.FieldToQE(field.ZERO_F)

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			matrixVal := c.qeAPI.VarToQE(MDS_MATRIX_CIRC[i])
			res1 := c.qeAPI.MulExtension(v[(i+r)%SPONGE_WIDTH], matrixVal)
			res = c.qeAPI.AddExtension(res, res1)
		}
	}

	matrixVal := c.qeAPI.VarToQE(MDS_MATRIX_DIAG[r])
	res = c.qeAPI.AddExtension(res, c.qeAPI.MulExtension(v[r], matrixVal))
	return res
}

func (c *PoseidonChip) mdsLayer(state_ PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = frontend.Variable(0)
	}

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			result[r] = c.mdsRowShf(r, state_)
		}
	}

	return result
}

func (c *PoseidonChip) MdsLayerExtension(state_ PoseidonStateExtension) PoseidonStateExtension {
	var result PoseidonStateExtension

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			sum := c.MdsRowShfExtension(r, state_)
			result[r] = sum
		}
	}

	return result
}

func (c *PoseidonChip) partialFirstConstantLayer(state PoseidonState) PoseidonState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = field.GoldilocksMulAdd(c.api, frontend.Variable(1), state[i], FAST_PARTIAL_FIRST_ROUND_CONSTANT[i])
		}
	}
	return state
}

func (c *PoseidonChip) PartialFirstConstantLayerExtension(state PoseidonStateExtension) PoseidonStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.qeAPI.AddExtension(state[i], c.qeAPI.VarToQE((FAST_PARTIAL_FIRST_ROUND_CONSTANT[i])))
		}
	}
	return state
}

func (c *PoseidonChip) mdsPartialLayerInit(state PoseidonState) PoseidonState {
	var result PoseidonState
	for i := 0; i < 12; i++ {
		result[i] = frontend.Variable(0)
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < SPONGE_WIDTH {
			for d := 1; d < 12; d++ {
				if d < SPONGE_WIDTH {
					t := FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1]
					result[d] = field.GoldilocksMulAdd(c.api, state[r], t, result[d])
				}
			}
		}
	}

	return result
}

func (c *PoseidonChip) MdsPartialLayerInitExtension(state PoseidonStateExtension) PoseidonStateExtension {
	var result PoseidonStateExtension
	for i := 0; i < 12; i++ {
		result[i] = c.qeAPI.FieldToQE(field.ZERO_F)
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < SPONGE_WIDTH {
			for d := 1; d < 12; d++ {
				if d < SPONGE_WIDTH {
					t := c.qeAPI.VarToQE(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1])
					result[d] = c.qeAPI.AddExtension(result[d], c.qeAPI.MulExtension(state[r], t))
				}
			}
		}
	}

	return result
}

func (c *PoseidonChip) mdsPartialLayerFast(state PoseidonState, r int) PoseidonState {
	dSum := ZERO_VAR
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_W_HATS_VARS[r][i-1]
			dSum = field.GoldilocksMulAdd(c.api, state[i], t, dSum)
		}
	}

	d := field.GoldilocksMulAdd(c.api, state[0], MDS0TO0_VAR, dSum)

	var result PoseidonState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = frontend.Variable(0)
	}

	result[0] = d

	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_VS[r][i-1]
			result[i] = field.GoldilocksMulAdd(c.api, state[0], t, state[i])
		}
	}

	return result
}

func (c *PoseidonChip) MdsPartialLayerFastExtension(state PoseidonStateExtension, r int) PoseidonStateExtension {
	s0 := state[0]
	mds0to0 := c.qeAPI.VarToQE(MDS0TO0)
	d := c.qeAPI.MulExtension(s0, mds0to0)
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := c.qeAPI.VarToQE(FAST_PARTIAL_ROUND_W_HATS[r][i-1])
			d = c.qeAPI.AddExtension(d, c.qeAPI.MulExtension(state[i], t))
		}
	}

	var result PoseidonStateExtension
	result[0] = d
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := c.qeAPI.VarToQE(FAST_PARTIAL_ROUND_VS[r][i-1])
			result[i] = c.qeAPI.AddExtension(c.qeAPI.MulExtension(state[0], t), state[i])
		}
	}

	return result
}
