package plonky2_verifier

import (
	"github.com/consensys/gnark/frontend"
)

type V = frontend.Variable

type Challenger struct {
	sponge_state: [SPONGE_WIDTH]V
	input_buffer: []V
	output_buffer: []V
}

func NewChallenger() Challenger {
	var sponge_state [SPONGE_WIDTH]V
	for i := 0; i < SPONGE_WIDTH; i++ {
		sponge_state[i] = 0
	}
	return Challenger {
		sponge_state: sponge_state,
		input_buffer: []V{},
		output_buffer: []V{},
	}
}

func (c *Challenger) observe_elements(elements []V) {
	for _, element := range elements {
		c.observe_element(element)
	}
}

func (c *Challenger) observe_hash(hash []V) {
	c.observe_elements(hash)
}

func (c *Challenger) observe_element(element V) {
	c.output_buffer = V[]{}
	c.input_buffer = append(c.input_buffer, element)
	if len(c.input_buffer) == SPONGE_RATE {
		c.duplexing()
	}
}

func (c *Challenger) observe_cap(cap [][]V) {
	for _, hash := range cap {
		c.observe_hash(hash)
	}
}

func (c *Challenger) duplexing() {
	if len(c.input_buffer) > SPONGE_RATE { panic("buffer too large") }

	for i, input := range c.input_buffer {
		c.sponge_state[i] = input
	}
	c.input_buffer = V[]{}

	c.sponge_state = poseidon(c.sponge_state)

	c.output_buffer = c.sponge_state[:SPONGE_RATE]
}

func (c *Challenger) get_challenge() V {
	if len(c.input_buffer) > 0 || len(c.output_buffer) == 0 {
		c.duplexing()
	}
	result := c.output_buffer[len(c.output_buffer) - 1]
	c.output_buffer = c.output_buffer[:len(c.output_buffer) - 1]
	return result
}

func (c *Challenger) get_n_challenges(n int) []V {
	result := make([]V, n)
	for i := 0; i < n; i++ {
		result[i] = c.get_challenge()
	}
	return result
}
