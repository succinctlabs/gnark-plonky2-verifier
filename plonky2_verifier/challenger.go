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

// pub struct Challenger {
//     sponge_state: [GoldilocksField; SPONGE_WIDTH],
//     input_buffer: Vec<GoldilocksField>,
//     output_buffer: Vec<GoldilocksField>
// }

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
//     pub fn new() -> Challenger {
//         return Challenger {
//             sponge_state: [GoldilocksField::ZERO; SPONGE_WIDTH],
//             input_buffer: Vec::with_capacity(SPONGE_RATE),
//             output_buffer: Vec::with_capacity(SPONGE_RATE)
//         };
//     }

func (c *Challenger) observe_elements(elements []V) {
	for _, element := range elements {
		c.observe_element(element)
	}
}
//     pub fn observe_elements(&mut self, elements: &[GoldilocksField]) {
//         for &element in elements {
//             self.observe_element(element);
//         }
//     }

func (c *Challenger) observe_hash(hash []V) {
	c.observe_elements(hash)
}
//     pub fn observe_hash(&mut self, hash: Vec<GoldilocksField>) {
//         self.observe_elements(&hash.to_vec())
//     }

func (c *Challenger) observe_element(element V) {
	c.output_buffer = V[]{}
	c.input_buffer = append(c.input_buffer, element)
	if len(c.input_buffer) == SPONGE_RATE {
		c.duplexing()
	}
}
//     pub fn observe_element(&mut self, element: GoldilocksField) {
//         self.output_buffer.clear();
//         self.input_buffer.push(element);
//         if self.input_buffer.len() == SPONGE_RATE {
//             self.duplexing();
//         }
//     }

func (c *Challenger) observe_cap(cap [][]V) {
	for _, hash := range cap {
		c.observe_hash(hash)
	}
}
//     pub fn observe_cap(&mut self, cap: &Vec<Vec<GoldilocksField>>) {
//         for hash in cap.into_iter() {
//             self.observe_hash(hash.clone());
//         }
//     }

func (c *Challenger) duplexing() {
	if len(c.input_buffer) > SPONGE_RATE { panic("buffer too large") }

	for i, input := range c.input_buffer {
		c.sponge_state[i] = input
	}
	c.input_buffer = V[]{}

	c.sponge_state = poseidon(c.sponge_state)

	c.output_buffer = c.sponge_state[:SPONGE_RATE]
}
//     fn duplexing(&mut self) {
//         assert!(self.input_buffer.len() <= SPONGE_RATE);

//         for (i, input) in self.input_buffer.drain(..).enumerate() {
//             self.sponge_state[i] = input;
//         }

//         self.sponge_state = poseidon(self.sponge_state);

//         self.output_buffer.clear();
//         self.output_buffer
//             .extend_from_slice(&self.sponge_state[0..SPONGE_RATE]);
//     }

func (c *Challenger) get_challenge() V {
	if len(c.input_buffer) > 0 || len(c.output_buffer) == 0 {
		c.duplexing()
	}
	result := c.output_buffer[len(c.output_buffer) - 1]
	c.output_buffer = c.output_buffer[:len(c.output_buffer) - 1]
	return result
}
//     pub fn get_challenge(&mut self) -> GoldilocksField {
//         if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
//             self.duplexing();
//         }

//         self.output_buffer
//             .pop()
//             .expect("Output buffer should be non-empty")
//     }

func (c *Challenger) get_n_challenges(n int) []V {
	result := make([]V, n)
	for i := 0; i < n; i++ {
		result[i] = c.get_challenge()
	}
	return result
}
//     pub fn get_n_challenges(&mut self, n: usize) -> Vec<GoldilocksField> {
//         (0..n).map(|_| self.get_challenge()).collect()
//     }
// }

