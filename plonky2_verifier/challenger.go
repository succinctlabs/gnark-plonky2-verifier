package plonky2_verifier

import (
	"fmt"
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"

	"github.com/consensys/gnark/frontend"
)

type ChallengerChip struct {
	api          frontend.API
	field        frontend.API
	poseidonChip poseidon.PoseidonChip
	spongeState  [poseidon.SPONGE_WIDTH]F
	inputBuffer  []F
	outputBuffer []F
}

func NewChallengerChip(api frontend.API, field frontend.API, poseidonChip poseidon.PoseidonChip) *ChallengerChip {
	var spongeState [poseidon.SPONGE_WIDTH]F
	var inputBuffer []F
	var outputBuffer []F
	return &ChallengerChip{
		api:          api,
		field:        field,
		poseidonChip: poseidonChip,
		spongeState:  spongeState,
		inputBuffer:  inputBuffer,
		outputBuffer: outputBuffer,
	}
}

func (c *ChallengerChip) ObserveElement(element F) {
	c.outputBuffer = clearBuffer(c.outputBuffer)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == poseidon.SPONGE_RATE {
		c.duplexing()
	}
}

func (c *ChallengerChip) ObserveElements(elements []F) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveHash(hash Hash) {
	c.ObserveElements(hash[:])
}

func (c *ChallengerChip) ObserveCap(cap []Hash) {
	for i := 0; i < len(cap); i++ {
		c.ObserveHash(cap[i])
	}
}

func (c *ChallengerChip) ObserveExtensionElement(element QuadraticExtension) {
	c.ObserveElements(element[:])
}

func (c *ChallengerChip) ObserveExtensionElements(elements []QuadraticExtension) {
	for i := 0; i < len(elements); i++ {
		c.ObserveExtensionElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveOpenings(openings FriOpenings) {
	for i := 0; i < len(openings.Batches); i++ {
		c.ObserveExtensionElements(openings.Batches[i].values)
	}
}

func (c *ChallengerChip) GetChallenge() F {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *ChallengerChip) GetNChallenges(n uint64) []F {
	challenges := make([]F, n)
	for i := uint64(0); i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func (c *ChallengerChip) GetExtensionChallenge() QuadraticExtension {
	values := c.GetNChallenges(2)
	return QuadraticExtension{values[0], values[1]}
}

func (c *ChallengerChip) GetHash() Hash {
	return [4]F{c.GetChallenge(), c.GetChallenge(), c.GetChallenge(), c.GetChallenge()}
}

func (c *ChallengerChip) GetFriChallenges(commitPhaseMerkleCaps []MerkleCap, finalPoly PolynomialCoeffs, powWitness F, degreeBits uint64, config FriConfig) FriChallenges {
	numFriQueries := config.NumQueryRounds
	friAlpha := c.GetExtensionChallenge()

	var friBetas []QuadraticExtension
	for i := 0; i < len(commitPhaseMerkleCaps); i++ {
		c.ObserveCap(commitPhaseMerkleCaps[i])
		friBetas = append(friBetas, c.GetExtensionChallenge())
	}

	c.ObserveExtensionElements(finalPoly.Coeffs)

	hash := c.GetHash()
	powInputs := append(hash[:], powWitness)

	friPowResponse := c.poseidonChip.HashNoPad(powInputs)[0]
	friQueryIndices := c.GetNChallenges(numFriQueries)

	return FriChallenges{
		FriAlpha:         friAlpha,
		FriBetas:         friBetas,
		FriPowResponse:   friPowResponse,
		FriQueryIndicies: friQueryIndices,
	}
}

func clearBuffer(buffer []F) []F {
	return make([]F, 0)
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
