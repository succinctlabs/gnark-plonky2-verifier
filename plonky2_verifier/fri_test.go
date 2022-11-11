package plonky2_verifier

import (
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestFriCircuit struct{}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs("./data/fibonacci/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./data/fibonacci/common_circuit_data.json")
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./data/fibonacci/verifier_only_circuit_data.json")

	field := NewFieldAPI(api)
	qe := NewQuadraticExtensionAPI(field, commonCircuitData.DegreeBits)
	poseidonChip := poseidon.NewPoseidonChip(api, field)
	friChip := NewFriChip(api, field, qe, poseidonChip, &commonCircuitData.FriParams)

	zeta := QuadraticExtension{
		NewFieldElementFromString("14887793628029982930"),
		NewFieldElementFromString("1136137158284059037"),
	}
	friChallenges := FriChallenges{
		FriAlpha: QuadraticExtension{
			NewFieldElementFromString("14641715242626918707"),
			NewFieldElementFromString("10574243340537902930"),
		},
		FriBetas:       []QuadraticExtension{},
		FriPowResponse: NewFieldElement(82451580476419),
		FriQueryIndicies: []F{
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
		},
	}

	initialMerkleCaps := []MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	friChip.VerifyFriProof(
		commonCircuitData.GetFriInstance(qe, zeta, commonCircuitData.DegreeBits),
		proofWithPis.Proof.Openings.ToFriOpenings(),
		&friChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)

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
