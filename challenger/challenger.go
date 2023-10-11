package challenger

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/fri"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

type Chip struct {
	api               frontend.API `gnark:"-"`
	poseidonChip      *poseidon.GoldilocksChip
	poseidonBN254Chip *poseidon.BN254Chip
	spongeState       [poseidon.SPONGE_WIDTH]gl.GoldilocksVariable
	inputBuffer       []gl.GoldilocksVariable
	outputBuffer      []gl.GoldilocksVariable
}

func NewChip(api frontend.API) *Chip {
	var spongeState [poseidon.SPONGE_WIDTH]gl.GoldilocksVariable
	var inputBuffer []gl.GoldilocksVariable
	var outputBuffer []gl.GoldilocksVariable
	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = gl.Zero()
	}
	poseidonChip := poseidon.NewGoldilocksChip(api)
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &Chip{
		api:               api,
		poseidonChip:      poseidonChip,
		poseidonBN254Chip: poseidonBN254Chip,
		spongeState:       spongeState,
		inputBuffer:       inputBuffer,
		outputBuffer:      outputBuffer,
	}
}

func (c *Chip) ObserveElement(element gl.GoldilocksVariable) {
	c.outputBuffer = clearBuffer(c.outputBuffer)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

func (c *Chip) ObserveElements(elements []gl.GoldilocksVariable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *Chip) ObserveHash(hash poseidon.GoldilocksHashOut) {
	elements := c.poseidonChip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *Chip) ObserveBN254Hash(hash poseidon.BN254HashOut) {
	elements := c.poseidonBN254Chip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *Chip) ObserveCap(cap []poseidon.BN254HashOut) {
	for i := 0; i < len(cap); i++ {
		c.ObserveBN254Hash(cap[i])
	}
}

func (c *Chip) ObserveExtensionElement(element gl.QuadraticExtensionVariable) {
	c.ObserveElements(element[:])
}

func (c *Chip) ObserveExtensionElements(elements []gl.QuadraticExtensionVariable) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *Chip) ObserveOpenings(openings fri.Openings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].Values)
	}
}

func (c *Chip) GetChallenge() gl.GoldilocksVariable {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *Chip) GetNChallenges(n uint64) []gl.GoldilocksVariable {
	challenges := make([]gl.GoldilocksVariable, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *Chip) GetExtensionChallenge() gl.QuadraticExtensionVariable {
	values := c.GetNChallenges(2)
	return gl.QuadraticExtensionVariable{values[0], values[1]}
}

func (c *Chip) GetHash() poseidon.GoldilocksHashOut {
	return [4]gl.GoldilocksVariable{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *Chip) GetFriChallenges(
	commitPhaseMerkleCaps []types.FriMerkleCap,
	finalPoly types.PolynomialCoeffs,
	powWitness gl.GoldilocksVariable,
	degreeBits uint64,
	config types.FriConfig,
) types.FriChallenges {
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

	return types.FriChallenges{
		FriAlpha:        friAlpha,
		FriBetas:        friBetas,
		FriPowResponse:  friPowResponse,
		FriQueryIndices: friQueryIndices,
	}
}

func clearBuffer(buffer []gl.GoldilocksVariable) []gl.GoldilocksVariable {
	return make([]gl.GoldilocksVariable, 0)
}

func (c *Chip) duplexing() {
	if len(c.inputBuffer) > poseidon.SPONGE_RATE {
		fmt.Println(len(c.inputBuffer))
		panic("something went wrong")
	}

	glApi := gl.NewGoldilocksApi(c.api)

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
