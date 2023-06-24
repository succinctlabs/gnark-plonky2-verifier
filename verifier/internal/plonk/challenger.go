package plonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
)

type ChallengerChip struct {
	api               frontend.API `gnark:"-"`
	poseidonChip      *poseidon.PoseidonChip
	poseidonBN254Chip *poseidon.PoseidonBN254Chip
	spongeState       [poseidon.SPONGE_WIDTH]gl.Variable
	inputBuffer       []gl.Variable
	outputBuffer      []gl.Variable
}

func NewChallengerChip(api frontend.API, poseidonChip *poseidon.PoseidonChip, poseidonBN254Chip *poseidon.PoseidonBN254Chip) *ChallengerChip {
	var spongeState [poseidon.SPONGE_WIDTH]gl.Variable
	var inputBuffer []gl.Variable
	var outputBuffer []gl.Variable

	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = gl.Zero()
	}

	return &ChallengerChip{
		api:               api,
		poseidonChip:      poseidonChip,
		poseidonBN254Chip: poseidonBN254Chip,
		spongeState:       spongeState,
		inputBuffer:       inputBuffer,
		outputBuffer:      outputBuffer,
	}
}

func (c *ChallengerChip) ObserveElement(element gl.Variable) {
	c.outputBuffer = clearBuffer(c.outputBuffer)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

func (c *ChallengerChip) ObserveElements(elements []gl.Variable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveHash(hash poseidon.PoseidonHashOut) {
	elements := c.poseidonChip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *ChallengerChip) ObserveBN254Hash(hash poseidon.PoseidonBN254HashOut) {
	elements := c.poseidonBN254Chip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *ChallengerChip) ObserveCap(cap []poseidon.PoseidonBN254HashOut) {
	for i := 0; i < len(cap); i++ {
		c.ObserveBN254Hash(cap[i])
	}
}

func (c *ChallengerChip) ObserveExtensionElement(element gl.QuadraticExtensionVariable) {
	c.ObserveElements(element[:])
}

func (c *ChallengerChip) ObserveExtensionElements(elements []gl.QuadraticExtensionVariable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveOpenings(openings fri.FriOpenings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].Values)
	}
}

func (c *ChallengerChip) GetChallenge() gl.Variable {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *ChallengerChip) GetNChallenges(n uint64) []gl.Variable {
	challenges := make([]gl.Variable, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *ChallengerChip) GetExtensionChallenge() gl.QuadraticExtensionVariable {
	values := c.GetNChallenges(2)
	return gl.QuadraticExtensionVariable{values[0], values[1]}
}

func (c *ChallengerChip) GetHash() poseidon.PoseidonHashOut {
	return [4]gl.Variable{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *ChallengerChip) GetFriChallenges(
	commitPhaseMerkleCaps []common.MerkleCap,
	finalPoly common.PolynomialCoeffs,
	powWitness gl.Variable,
	degreeBits uint64,
	config common.FriConfig,
) common.FriChallenges {
	numFriQueries := config.NumQueryRounds
	friAlpha := c.GetExtensionChallenge()

	var friBetas []gl.QuadraticExtensionVariable
	for i := 0; i < len(commitPhaseMerkleCaps); i++ {
		c.ObserveCap(commitPhaseMerkleCaps[i])
		friBetas = append(friBetas, c.GetExtensionChallenge())
	}

	c.ObserveExtensionElements(finalPoly.Coeffs)
	c.ObserveElement(powWitness)

	friPowResponse := c.GetChallenge()
	friQueryIndices := c.GetNChallenges(numFriQueries)

	return common.FriChallenges{
		FriAlpha:        friAlpha,
		FriBetas:        friBetas,
		FriPowResponse:  friPowResponse,
		FriQueryIndices: friQueryIndices,
	}
}

func clearBuffer(buffer []gl.Variable) []gl.Variable {
	return make([]gl.Variable, 0)
}

func (c *ChallengerChip) duplexing() {
	if len(c.inputBuffer) > poseidon.SPONGE_RATE {
		fmt.Println(len(c.inputBuffer))
		panic("something went wrong")
	}

	glApi := gl.NewChip(c.api)

	for i := 0; i < len(c.inputBuffer); i++ {
		c.spongeState[i] = glApi.Reduce(c.inputBuffer[i])
	}
	c.inputBuffer = clearBuffer(c.inputBuffer)
	c.spongeState = c.poseidonChip.Poseidon(c.spongeState)
	clearBuffer(c.outputBuffer)
	for i := 0; i < poseidon.SPONGE_RATE; i++ {
		c.outputBuffer = append(c.outputBuffer, c.spongeState[i])
	}
}
