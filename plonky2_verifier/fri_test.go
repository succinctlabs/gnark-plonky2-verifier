package plonky2_verifier

import (
	. "gnark-ed25519/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestFriCircuit struct{}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs("./data/fibonacci/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./data/fibonacci/common_circuit_data.json")

	field := NewFieldAPI(api)

	friChip := NewFriChip(api, field, commonCircuitData.Config.FriConfig)
	friChip.VerifyFriProof(&proofWithPis.Proof.OpeningProof)
	return nil
}

func TestFriProof(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestFriCircuit{}
		witness := TestFriCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
