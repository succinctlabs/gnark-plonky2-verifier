package plonky2_verifier

import (
	. "gnark-ed25519/field"
	. "gnark-ed25519/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestVerifierCircuit struct{}

func (circuit *TestVerifierCircuit) Define(api frontend.API) error {
	field := NewFieldAPI(api)
	poseidonChip := NewPoseidonChip(api, field)
	verifierChip := VerifierChip{api: api, field: field, poseidonChip: *poseidonChip}
	proofWithPis := DeserializeProofWithPublicInputs("./data/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./data/common_circuit_data.json")
	verfierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./data/verifier_only_circuit_data.json")
	verifierChip.Verify(proofWithPis, verfierOnlyCircuitData, commonCircuitData)
	panic("look at stdout")
	return nil
}

func TestVerifierWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierCircuit{}
		witness := TestVerifierCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
