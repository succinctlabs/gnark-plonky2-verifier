package verifier

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type ExampleVerifierCircuit struct {
	PublicInputs            []gl.Variable                     `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *ExampleVerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData)

	return nil
}
