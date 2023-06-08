package poseidon

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

const fullRounds = 8
const partialRounds = 56
const spongeWidth = 4
const spongeRate = 3

type PoseidonBN128Chip struct {
	api      frontend.API   `gnark:"-"`
	fieldAPI field.FieldAPI `gnark:"-"`
}

type PoseidonBN128State = [spongeWidth]frontend.Variable
type PoseidonBN128HashOut = frontend.Variable

// This implementation is based on the following implementation:
// https://github.com/iden3/go-iden3-crypto/blob/e5cf066b8be3da9a3df9544c65818df189fdbebe/poseidon/poseidon.go
func NewPoseidonBN128Chip(api frontend.API, fieldAPI field.FieldAPI) *PoseidonBN128Chip {
	return &PoseidonBN128Chip{api: api, fieldAPI: fieldAPI}
}

func (c *PoseidonBN128Chip) Poseidon(state PoseidonBN128State) PoseidonBN128State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *PoseidonBN128Chip) HashNoPad(input []field.F) PoseidonBN128HashOut {
	state := PoseidonBN128State{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
	}

	for i := 0; i < len(input); i += spongeRate * 3 {
		endI := c.min(len(input), i+spongeRate*3)
		rateChunk := input[i:endI]
		for j, stateIdx := 0, 0; j < len(rateChunk); j, stateIdx = j+3, stateIdx+1 {
			endJ := c.min(len(rateChunk), j+3)
			bn128Chunk := rateChunk[j:endJ]

			bits := []frontend.Variable{}
			for k := 0; k < len(bn128Chunk); k++ {
				bn128Chunk[k] = c.fieldAPI.Reduce(bn128Chunk[k])
				bits = append(bits, c.fieldAPI.ToBits(bn128Chunk[k])...)
			}

			state[stateIdx+1] = c.api.FromBinary(bits...)
		}

		state = c.Poseidon(state)
	}

	return PoseidonBN128HashOut(state[0])
}

func (c *PoseidonBN128Chip) HashOrNoop(input []field.F) PoseidonBN128HashOut {
	if len(input) <= 3 {
		returnVal := frontend.Variable(0)

		alpha := new(big.Int).SetInt64(1 << 32)
		for i, inputElement := range input {
			returnVal = c.api.Add(returnVal, c.api.Mul(inputElement, alpha.Exp(alpha, big.NewInt(int64(i)), nil)))
		}

		return PoseidonBN128HashOut(returnVal)
	} else {
		return c.HashNoPad(input)
	}
}

func (c *PoseidonBN128Chip) TwoToOne(left PoseidonBN128HashOut, right PoseidonBN128HashOut) PoseidonBN128HashOut {
	var inputs PoseidonBN128State
	inputs[0] = frontend.Variable(0)
	inputs[1] = frontend.Variable(0)
	inputs[2] = left
	inputs[3] = right
	state := c.Poseidon(inputs)
	return state[0]
}

func (c *PoseidonBN128Chip) ToVec(hash PoseidonBN128HashOut) []field.F {
	bits := c.api.ToBinary(hash)

	returnElements := []field.F{}

	// Split into 7 byte chunks, since 8 byte chunks can result in collisions
	chunkSize := 56
	for i := 0; i < len(bits); i += chunkSize {
		maxIdx := c.min(len(bits), i+chunkSize)
		bitChunk := bits[i:maxIdx]
		returnElements = append(returnElements, c.fieldAPI.FromBits(bitChunk...))
	}

	return returnElements
}

func (c *PoseidonBN128Chip) min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

func (c *PoseidonBN128Chip) fullRounds(state PoseidonBN128State, isFirst bool) PoseidonBN128State {
	for i := 0; i < fullRounds/2-1; i++ {
		state = c.exp5state(state)
		if isFirst {
			state = c.ark(state, (i+1)*spongeWidth)
		} else {
			state = c.ark(state, (fullRounds/2+1)*spongeWidth+partialRounds+i*spongeWidth)
		}
		state = c.mix(state, mMatrix)
	}

	state = c.exp5state(state)
	if isFirst {
		state = c.ark(state, (fullRounds/2)*spongeWidth)
		state = c.mix(state, pMatrix)
	} else {
		state = c.mix(state, mMatrix)
	}

	return state
}

func (c *PoseidonBN128Chip) partialRounds(state PoseidonBN128State) PoseidonBN128State {
	for i := 0; i < partialRounds; i++ {
		state[0] = c.exp5(state[0])
		state[0] = c.api.Add(state[0], cConstants[(fullRounds/2+1)*spongeWidth+i])

		var mul frontend.Variable
		newState0 := frontend.Variable(0)
		for j := 0; j < spongeWidth; j++ {
			mul = c.api.Mul(sConstants[(spongeWidth*2-1)*i+j], state[j])
			newState0 = c.api.Add(newState0, mul)
		}

		for k := 1; k < spongeWidth; k++ {
			mul = c.api.Mul(state[0], sConstants[(spongeWidth*2-1)*i+spongeWidth+k-1])
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
	for i := 0; i < spongeWidth; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *PoseidonBN128Chip) mix(state_ PoseidonBN128State, constantMatrix [][]*big.Int) PoseidonBN128State {
	var mul frontend.Variable
	var result PoseidonBN128State

	for i := 0; i < spongeWidth; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < spongeWidth; i++ {
		for j := 0; j < spongeWidth; j++ {
			mul = c.api.Mul(constantMatrix[j][i], state_[j])
			result[i] = c.api.Add(result[i], mul)
		}
	}

	return result
}
