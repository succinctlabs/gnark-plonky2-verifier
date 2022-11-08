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

	if len(proofChallenges.FriChallenges.FriBetas) != 0 {
		panic("There should be no fri betas")
	}

	// This test is commented out because pow_witness is randomized between runs of the prover.
	// expectedPowResponse := NewFieldElementFromString("92909863298412")
	// c.field.AssertIsEqual(proofChallenges.FriChallenges.FriPowResponse, expectedPowResponse)

	expectedFriQueryIndices := [...]F{
		NewFieldElement(6790812084677375942),
		NewFieldElement(12394212020331474798),
		NewFieldElement(16457600747000998582),
		NewFieldElement(1543271328932331916),
		NewFieldElement(12115726870906958644),
		NewFieldElement(6775897107605342797),
		NewFieldElement(15989401564746021030),
		NewFieldElement(10691676456016926845),
		NewFieldElement(1632499470630032007),
		NewFieldElement(1317292355445098328),
		NewFieldElement(18391440812534384252),
		NewFieldElement(17321705613231354333),
		NewFieldElement(6176487551308859603),
		NewFieldElement(7119835651572002873),
		NewFieldElement(3903019169623116693),
		NewFieldElement(4886491111111487546),
		NewFieldElement(4087641893164620518),
		NewFieldElement(13801643080324181364),
		NewFieldElement(16993775312274189321),
		NewFieldElement(9268202926222765679),
		NewFieldElement(10683001302406181735),
		NewFieldElement(13359465725531647963),
		NewFieldElement(4523327590105620849),
		NewFieldElement(4883588003760409588),
		NewFieldElement(187699146998097671),
		NewFieldElement(14489263557623716717),
		NewFieldElement(11748359318238148146),
		NewFieldElement(13636347200053048758),
	}

	if len(expectedFriQueryIndices) != len(proofChallenges.FriChallenges.FriQueryIndicies) {
		panic("len(expectedFriQueryIndices) != len(proofChallenges.FriChallenges.FriQueryIndicies)")
	}

	for i := 0; i < len(expectedFriQueryIndices); i++ {
		c.field.AssertIsEqual(expectedFriQueryIndices[i], proofChallenges.FriChallenges.FriQueryIndicies[i])
	}
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
