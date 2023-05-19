package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"

	"github.com/consensys/gnark/frontend"
)

type ChallengerChip struct {
	api          frontend.API `gnark:"-"`
	field        frontend.API `gnark:"-"`
	poseidonChip *poseidon.PoseidonChip
	spongeState  [poseidon.SPONGE_WIDTH]field.F
	inputBuffer  []field.F
	outputBuffer []field.F
}

func NewChallengerChip(api frontend.API, fieldAPI frontend.API, poseidonChip *poseidon.PoseidonChip) *ChallengerChip {
	var spongeState [poseidon.SPONGE_WIDTH]field.F
	var inputBuffer []field.F
	var outputBuffer []field.F

	for i := 0; i < poseidon.SPONGE_WIDTH; i++ {
		spongeState[i] = field.ZERO_F
	}

	return &ChallengerChip{
		api:          api,
		field:        fieldAPI,
		poseidonChip: poseidonChip,
		spongeState:  spongeState,
		inputBuffer:  inputBuffer,
		outputBuffer: outputBuffer,
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

func (c *ChallengerChip) ObserveHash(hash poseidon.Hash) {
	c.ObserveElements(hash[:])
}

func (c *ChallengerChip) ObserveCap(cap []poseidon.Hash) {
	for i := 0; i < len(cap); i++ {
		c.ObserveHash(cap[i])
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

func (c *ChallengerChip) ObserveOpenings(openings FriOpenings) {
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

func (c *ChallengerChip) GetHash() poseidon.Hash {
	return [4]field.F{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *ChallengerChip) GetFriChallenges(commitPhaseMerkleCaps []MerkleCap, finalPoly PolynomialCoeffs, powWitness field.F, degreeBits uint64, config FriConfig) FriChallenges {
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

	return FriChallenges{
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

	for i := 0; i < len(c.inputBuffer); i++ {
		c.spongeState[i] = c.inputBuffer[i]
	}
	c.inputBuffer = clearBuffer(c.inputBuffer)
	c.spongeState = c.poseidonChip.Poseidon(c.spongeState)
	clearBuffer(c.outputBuffer)
	for i := 0; i < poseidon.SPONGE_RATE; i++ {
		c.outputBuffer = append(c.outputBuffer, c.spongeState[i])
		// c.outputBuffer[i] = c.spongeState[i]
	}
}
