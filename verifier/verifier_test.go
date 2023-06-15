package verifier_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestVerifierCircuit struct {
	Proof        common.Proof
	PublicInputs []field.F `gnark:",public"`

	verifierChip       *verifier.VerifierChip `gnark:"-"`
	plonky2CircuitName string                 `gnark:"-"`
}

func (c *TestVerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./data/" + c.plonky2CircuitName + "/"
	commonCircuitData := utils.DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	c.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	c.verifierChip.Verify(c.Proof, c.PublicInputs, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func TestStepVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		plonky2Circuit := "step"
		proofWithPis := utils.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		circuit := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis.Proof,
			PublicInputs:       proofWithPis.PublicInputs,
		}

		proofWithPis2 := utils.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		witness := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis2.Proof,
			PublicInputs:       proofWithPis2.PublicInputs,
		}

		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}
	testCase()
}
