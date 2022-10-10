package plonky2_verifier

import (
	"fmt"
	. "gnark-ed25519/goldilocks"
	"gnark-ed25519/poseidon"
	. "gnark-ed25519/poseidon"

	"github.com/consensys/gnark/frontend"
)

type ChallengerChip struct {
	api          frontend.API
	field        frontend.API
	poseidonChip PoseidonChip
	spongeState  [SPONGE_WIDTH]GoldilocksElement
	inputBuffer  []GoldilocksElement
	outputBuffer []GoldilocksElement
}

func NewChallengerChip(api frontend.API, field frontend.API, poseidonChip PoseidonChip) *ChallengerChip {
	var spongeState [SPONGE_WIDTH]GoldilocksElement
	var inputBuffer []GoldilocksElement
	var outputBuffer []GoldilocksElement
	return &ChallengerChip{
		api:          api,
		field:        field,
		poseidonChip: poseidonChip,
		spongeState:  spongeState,
		inputBuffer:  inputBuffer,
		outputBuffer: outputBuffer,
	}
}

func (c *ChallengerChip) ObserveElement(element GoldilocksElement) {
	c.outputBuffer = clearBuffer(c.outputBuffer)
	c.inputBuffer = append(c.inputBuffer, element)
	if len(c.inputBuffer) == SPONGE_RATE {
		c.duplexing()
	}
}

func (c *ChallengerChip) ObserveElements(elements []GoldilocksElement) {
	for i := 0; i < len(elements); i++ {
		c.ObserveElement(elements[i])
	}
}

func (c *ChallengerChip) ObserveHash(hash HashOutput) {
	c.ObserveElements(hash[:])
}

func (c *ChallengerChip) ObserveCap(cap []HashOutput) {
	for i := 0; i < len(cap); i++ {
		c.ObserveHash(cap[i])
	}
}

func (c *ChallengerChip) GetChallenge() GoldilocksElement {
	if len(c.inputBuffer) != 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}

	challenge := c.outputBuffer[len(c.outputBuffer)-1]
	c.outputBuffer = c.outputBuffer[:len(c.outputBuffer)-1]

	return challenge
}

func (c *ChallengerChip) GetNChallenges(n int) []GoldilocksElement {
	challenges := make([]GoldilocksElement, n)
	for i := 0; i < n; i++ {
		challenges[i] = c.GetChallenge()
	}
	return challenges
}

func clearBuffer(buffer []GoldilocksElement) []GoldilocksElement {
	return make([]GoldilocksElement, 0)
}

func (c *ChallengerChip) duplexing() {
	if len(c.inputBuffer) > SPONGE_RATE {
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
