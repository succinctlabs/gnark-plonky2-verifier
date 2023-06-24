package poseidon

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
)

const fullRounds = 8
const partialRounds = 56
const spongeWidth = 4
const spongeRate = 3

type PoseidonBN254Chip struct {
	api frontend.API `gnark:"-"`
	gl  gl.Chip      `gnark:"-"`
}

type PoseidonBN254State = [spongeWidth]frontend.Variable
type PoseidonBN254HashOut = frontend.Variable

// This implementation is based on the following implementation:
// https://github.com/iden3/go-iden3-crypto/blob/e5cf066b8be3da9a3df9544c65818df189fdbebe/poseidon/poseidon.go
func NewPoseidonBN254Chip(api frontend.API) *PoseidonBN254Chip {
	return &PoseidonBN254Chip{api: api, gl: *gl.NewChip(api)}
}

func (c *PoseidonBN254Chip) Poseidon(state PoseidonBN254State) PoseidonBN254State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *PoseidonBN254Chip) HashNoPad(input []gl.Variable) PoseidonBN254HashOut {
	state := PoseidonBN254State{
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
			bn254Chunk := rateChunk[j:endJ]

			bits := []frontend.Variable{}
			for k := 0; k < len(bn254Chunk); k++ {
				bn254Chunk[k] = c.gl.Reduce(bn254Chunk[k])
				bits = append(bits, c.api.ToBinary(bn254Chunk[k].Limb, 64)...)
			}

			state[stateIdx+1] = c.api.FromBinary(bits...)
		}

		state = c.Poseidon(state)
	}

	return PoseidonBN254HashOut(state[0])
}

func (c *PoseidonBN254Chip) HashOrNoop(input []gl.Variable) PoseidonBN254HashOut {
	if len(input) <= 3 {
		returnVal := frontend.Variable(0)

		alpha := new(big.Int).SetInt64(1 << 32)
		for i, inputElement := range input {
			returnVal = c.api.Add(returnVal, c.api.Mul(inputElement, alpha.Exp(alpha, big.NewInt(int64(i)), nil)))
		}

		return PoseidonBN254HashOut(returnVal)
	} else {
		return c.HashNoPad(input)
	}
}

func (c *PoseidonBN254Chip) TwoToOne(left PoseidonBN254HashOut, right PoseidonBN254HashOut) PoseidonBN254HashOut {
	var inputs PoseidonBN254State
	inputs[0] = frontend.Variable(0)
	inputs[1] = frontend.Variable(0)
	inputs[2] = left
	inputs[3] = right
	state := c.Poseidon(inputs)
	return state[0]
}

func (c *PoseidonBN254Chip) ToVec(hash PoseidonBN254HashOut) []gl.Variable {
	bits := c.api.ToBinary(hash)

	returnElements := []gl.Variable{}

	// Split into 7 byte chunks, since 8 byte chunks can result in collisions
	chunkSize := 56
	for i := 0; i < len(bits); i += chunkSize {
		maxIdx := c.min(len(bits), i+chunkSize)
		bitChunk := bits[i:maxIdx]
		returnElements = append(returnElements, gl.NewVariable(c.api.FromBinary(bitChunk...)))
	}

	return returnElements
}

func (c *PoseidonBN254Chip) min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

func (c *PoseidonBN254Chip) fullRounds(state PoseidonBN254State, isFirst bool) PoseidonBN254State {
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

func (c *PoseidonBN254Chip) partialRounds(state PoseidonBN254State) PoseidonBN254State {
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

func (c *PoseidonBN254Chip) ark(state PoseidonBN254State, it int) PoseidonBN254State {
	var result PoseidonBN254State

	for i := 0; i < len(state); i++ {
		result[i] = c.api.Add(state[i], cConstants[it+i])
	}

	return result
}

func (c *PoseidonBN254Chip) exp5(x frontend.Variable) frontend.Variable {
	x2 := c.api.Mul(x, x)
	x4 := c.api.Mul(x2, x2)
	return c.api.Mul(x4, x)
}

func (c *PoseidonBN254Chip) exp5state(state PoseidonBN254State) PoseidonBN254State {
	for i := 0; i < spongeWidth; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *PoseidonBN254Chip) mix(state_ PoseidonBN254State, constantMatrix [][]*big.Int) PoseidonBN254State {
	var mul frontend.Variable
	var result PoseidonBN254State

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
