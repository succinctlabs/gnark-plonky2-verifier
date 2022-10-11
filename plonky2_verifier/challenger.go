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

func (c *ChallengerChip) GetChallenge() F {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *ChallengerChip) GetNChallenges(n int) []F {
	challenges := make([]F, n)
	for i := 0; i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
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
