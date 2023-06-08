package plonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
)

type ChallengerChip struct {
	api               frontend.API   `gnark:"-"`
	field             field.FieldAPI `gnark:"-"`
	poseidonChip      *poseidon.PoseidonChip
	poseidonBN128Chip *poseidon.PoseidonBN128Chip
	spongeState       [poseidon.SPONGE_WIDTH]frontend.Variable
	inputBuffer       []field.F
	outputBuffer      []field.F
}

func NewChallengerChip(api frontend.API, fieldAPI field.FieldAPI, poseidonChip *poseidon.PoseidonChip, poseidonBN128Chip *poseidon.PoseidonBN128Chip) *ChallengerChip {
	var spongeState [poseidon.SPONGE_WIDTH]frontend.Variable
	var inputBuffer []field.F
	var outputBuffer []field.F

	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = frontend.Variable(0)
	}

	return &ChallengerChip{
		api:               api,
		field:             fieldAPI,
		poseidonChip:      poseidonChip,
		poseidonBN128Chip: poseidonBN128Chip,
		spongeState:       spongeState,
		inputBuffer:       inputBuffer,
		outputBuffer:      outputBuffer,
	}
}

func (c *ChallengerChip) ObserveElement(element field.F) {
	c.outputBuffer = clearBuffer(c.outputBuffer)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

func (c *ChallengerChip) ObserveElements(elements []field.F) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveHash(hash poseidon.PoseidonHashOut) {
	elements := c.poseidonChip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *ChallengerChip) ObserveBN128Hash(hash poseidon.PoseidonBN128HashOut) {
	elements := c.poseidonBN128Chip.ToVec(hash)
	c.ObserveElements(elements)
}

func (c *ChallengerChip) ObserveCap(cap []poseidon.PoseidonBN128HashOut) {
	for i := 0; i < len(cap); i++ {
		c.ObserveBN128Hash(cap[i])
	}
}

func (c *ChallengerChip) ObserveExtensionElement(element field.QuadraticExtension) {
	c.ObserveElements(element[:])
}

func (c *ChallengerChip) ObserveExtensionElements(elements []field.QuadraticExtension) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveOpenings(openings fri.FriOpenings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].Values)
	}
}

func (c *ChallengerChip) GetChallenge() field.F {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *ChallengerChip) GetNChallenges(n uint64) []field.F {
	challenges := make([]field.F, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *ChallengerChip) GetExtensionChallenge() field.QuadraticExtension {
	values := c.GetNChallenges(2)
	return field.QuadraticExtension{values[0], values[1]}
}

func (c *ChallengerChip) GetHash() poseidon.PoseidonHashOut {
	return [4]field.F{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *ChallengerChip) GetFriChallenges(commitPhaseMerkleCaps []common.MerkleCap, finalPoly common.PolynomialCoeffs, powWitness field.F, degreeBits uint64, config common.FriConfig) common.FriChallenges {
	numFriQueries := config.NumQueryRounds
	friAlpha := c.GetExtensionChallenge()

	var friBetas []field.QuadraticExtension
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

func clearBuffer(buffer []field.F) []field.F {
	return make([]field.F, 0)
}

func (c *ChallengerChip) duplexing() {
	if len(c.inputBuffer) > poseidon.SPONGE_RATE {
		fmt.Println(len(c.inputBuffer))
		panic("something went wrong")
	}

	c.inputBuffer = clearBuffer(c.inputBuffer)
	for i := 0; i < len(c.inputBuffer); i++ {
		c.spongeState[i] = c.field.Reduce(c.inputBuffer[i]).Limbs[0]
	}
	c.spongeState = c.poseidonChip.Poseidon(c.spongeState)
	clearBuffer(c.outputBuffer)
	for i := 0; i < poseidon.SPONGE_RATE; i++ {
		c.outputBuffer = append(c.outputBuffer, c.field.NewElement(c.spongeState[i]))
	}
}
