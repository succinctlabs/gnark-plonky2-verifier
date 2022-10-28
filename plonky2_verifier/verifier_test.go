package plonky2_verifier

import (
	. "gnark-ed25519/field"
	. "gnark-ed25519/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestVerifierCircuit struct{}

func (c *VerifierChip) GetChallengesSanityCheck(proofWithPis ProofWithPublicInputs, verifierData VerifierOnlyCircuitData, commonData CommonCircuitData) {
	publicInputsHash := c.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := c.GetChallenges(proofWithPis, publicInputsHash, commonData)

	expectedPublicInputsHash := [4]F{
		NewFieldElementFromString("8416658900775745054"),
		NewFieldElementFromString("12574228347150446423"),
		NewFieldElementFromString("9629056739760131473"),
		NewFieldElementFromString("3119289788404190010"),
	}

	for i := 0; i < 4; i++ {
		c.field.AssertIsEqual(publicInputsHash[i], expectedPublicInputsHash[i])
	}

	expectedPlonkBetas := [2]F{
		NewFieldElementFromString("4678728155650926271"),
		NewFieldElementFromString("13611962404289024887"),
	}

	for i := 0; i < 2; i++ {
		c.field.AssertIsEqual(proofChallenges.PlonkBetas[i], expectedPlonkBetas[i])
	}

	expectedPlonkGammas := [2]F{
		NewFieldElementFromString("13237663823305715949"),
		NewFieldElementFromString("15389314098328235145"),
	}

	for i := 0; i < 2; i++ {
		c.field.AssertIsEqual(proofChallenges.PlonkGammas[i], expectedPlonkGammas[i])
	}

	expectedPlonkAlphas := [2]F{
		NewFieldElementFromString("14505919539124304197"),
		NewFieldElementFromString("1695455639263736117"),
	}

	for i := 0; i < 2; i++ {
		c.field.AssertIsEqual(proofChallenges.PlonkAlphas[i], expectedPlonkAlphas[i])
	}

	expectedPlonkZetas := [2]F{
		NewFieldElementFromString("14887793628029982930"),
		NewFieldElementFromString("1136137158284059037"),
	}

	for i := 0; i < 2; i++ {
		c.field.AssertIsEqual(proofChallenges.PlonkZeta[i], expectedPlonkZetas[i])
	}

	expectedFriAlpha := [2]F{
		NewFieldElementFromString("14641715242626918707"),
		NewFieldElementFromString("10574243340537902930"),
	}

	for i := 0; i < 2; i++ {
		c.field.AssertIsEqual(proofChallenges.FriChallenges.FriAlpha[i], expectedFriAlpha[i])
	}

	// This test is commented out because pow_witness is randomized between runs of the prover.
	// expectedPowResponse := NewFieldElementFromString("92909863298412")
	// c.field.AssertIsEqual(proofChallenges.FriChallenges.FriPowResponse, expectedPowResponse)
}

func (circuit *TestVerifierCircuit) Define(api frontend.API) error {
	field := NewFieldAPI(api)
	poseidonChip := NewPoseidonChip(api, field)
	verifierChip := VerifierChip{api: api, field: field, poseidonChip: *poseidonChip}
	proofWithPis := DeserializeProofWithPublicInputs("./data/fibonacci/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./data/fibonacci/common_circuit_data.json")
	verfierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./data/fibonacci/verifier_only_circuit_data.json")
	verifierChip.GetChallengesSanityCheck(proofWithPis, verfierOnlyCircuitData, commonCircuitData)
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
