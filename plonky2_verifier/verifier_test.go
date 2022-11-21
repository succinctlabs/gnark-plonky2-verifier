package plonky2_verifier

import (
	. "gnark-ed25519/field"
	. "gnark-ed25519/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestVerifierCircuit struct {
	fieldAPI frontend.API           `gnark:"-"`
	qeAPI    *QuadraticExtensionAPI `gnark:"-"`
	hashAPI  *HashAPI               `gnark:"-"`

	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`

	numChallenges uint64 `gnark:"-"`
	numFriQueries uint64 `gnark:"-"`

	t *testing.T `gnark:"-"`

	expectedPublicInputsHash Hash
	expectedPlonkBetas       []F // slice length == num challenges
	expectedPlonkGammas      []F // slice length == num challenges
	expectedPlonkAlphas      []F // slice length == num challenges
	expectedPlonkZeta        QuadraticExtension
	expectedFriAlpha         QuadraticExtension
	expectedFriBetas         []QuadraticExtension // slice length == num fri rounds
	expectedFriQueryIndices  []F                  // slice length == num fri queries

	verifierChip *VerifierChip
}

func (c *TestVerifierCircuit) GetChallengesSanityCheck(
	proofWithPis ProofWithPublicInputs,
	verifierData VerifierOnlyCircuitData,
	commonData CommonCircuitData,
) {
	publicInputsHash := c.verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := c.verifierChip.GetChallenges(proofWithPis, publicInputsHash, commonData)

	c.hashAPI.AssertIsEqualHash(publicInputsHash, c.expectedPublicInputsHash)

	if len(proofChallenges.PlonkBetas) != int(c.numChallenges) {
		c.t.Errorf("len(PlonkBetas) should equal numChallenges")
	}
	for i := 0; i < int(c.numChallenges); i++ {
		c.fieldAPI.AssertIsEqual(proofChallenges.PlonkBetas[i], c.expectedPlonkBetas[i])
	}

	if len(proofChallenges.PlonkGammas) != int(c.numChallenges) {
		c.t.Errorf("len(PlonkGammas) should equal numChallenges")
	}
	for i := 0; i < int(c.numChallenges); i++ {
		c.fieldAPI.AssertIsEqual(proofChallenges.PlonkGammas[i], c.expectedPlonkGammas[i])
	}

	if len(proofChallenges.PlonkAlphas) != int(c.numChallenges) {
		c.t.Errorf("len(PlonkAlphas) should equal numChallenges")
	}
	for i := 0; i < int(c.numChallenges); i++ {
		c.fieldAPI.AssertIsEqual(proofChallenges.PlonkAlphas[i], c.expectedPlonkAlphas[i])
	}

	c.qeAPI.AssertIsEqual(proofChallenges.PlonkZeta, c.expectedPlonkZeta)

	c.qeAPI.AssertIsEqual(proofChallenges.FriChallenges.FriAlpha, c.expectedFriAlpha)

	if len(proofChallenges.FriChallenges.FriBetas) != len(commonData.FriParams.ReductionArityBits) {
		c.t.Errorf("len(PlonkAlphas) should equal num fri rounds")
	}
	for i := 0; i < len(commonData.FriParams.ReductionArityBits); i++ {
		c.qeAPI.AssertIsEqual(proofChallenges.FriChallenges.FriBetas[i], c.expectedFriBetas[i])
	}

	// This test is commented out because pow_witness is randomized between runs of the prover.
	// expectedPowResponse := NewFieldElementFromString("92909863298412")
	// c.field.AssertIsEqual(proofChallenges.FriChallenges.FriPowResponse, expectedPowResponse)

	if len(proofChallenges.FriChallenges.FriQueryIndicies) != int(c.numFriQueries) {
		c.t.Errorf("len(expectedFriQueryIndices) should equal num fri queries")
	}

	for i := 0; i < int(c.numFriQueries); i++ {
		c.fieldAPI.AssertIsEqual(c.expectedFriQueryIndices[i], proofChallenges.FriChallenges.FriQueryIndicies[i])
	}
}

func (c *TestVerifierCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs(c.proofWithPIsFilename)
	commonCircuitData := DeserializeCommonCircuitData(c.commonCircuitDataFilename)
	verfierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(c.verifierOnlyCircuitDataFilename)

	c.numChallenges = commonCircuitData.Config.NumChallenges
	c.numFriQueries = commonCircuitData.FriParams.Config.NumQueryRounds

	c.fieldAPI = NewFieldAPI(api)
	c.qeAPI = NewQuadraticExtensionAPI(c.fieldAPI, commonCircuitData.DegreeBits)
	c.hashAPI = NewHashAPI(c.fieldAPI)
	poseidonChip := NewPoseidonChip(api, c.fieldAPI)
	c.verifierChip = &VerifierChip{api: api, fieldAPI: c.fieldAPI, qeAPI: c.qeAPI, poseidonChip: poseidonChip}

	c.GetChallengesSanityCheck(proofWithPis, verfierOnlyCircuitData, commonCircuitData)
	return nil
}

func TestFibonacciVerifierWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierCircuit{
			proofWithPIsFilename:            "./data/fibonacci/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/fibonacci/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/fibonacci/verifier_only_circuit_data.json",
			t:                               t,

			expectedPublicInputsHash: Hash{
				NewFieldElementFromString("8416658900775745054"),
				NewFieldElementFromString("12574228347150446423"),
				NewFieldElementFromString("9629056739760131473"),
				NewFieldElementFromString("3119289788404190010"),
			},

			expectedPlonkBetas: []F{
				NewFieldElementFromString("4678728155650926271"),
				NewFieldElementFromString("13611962404289024887"),
			},

			expectedPlonkGammas: []F{
				NewFieldElementFromString("13237663823305715949"),
				NewFieldElementFromString("15389314098328235145"),
			},

			expectedPlonkAlphas: []F{
				NewFieldElementFromString("14505919539124304197"),
				NewFieldElementFromString("1695455639263736117"),
			},

			expectedPlonkZeta: QuadraticExtension{
				NewFieldElementFromString("14887793628029982930"),
				NewFieldElementFromString("1136137158284059037"),
			},

			expectedFriAlpha: QuadraticExtension{
				NewFieldElementFromString("14641715242626918707"),
				NewFieldElementFromString("10574243340537902930"),
			},

			expectedFriBetas: []QuadraticExtension{},

			expectedFriQueryIndices: []F{
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
		witness := TestVerifierCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestDummyVerifierWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierCircuit{
			proofWithPIsFilename:            "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/dummy_2^14_gates/verifier_only_circuit_data.json",
			t:                               t,

			expectedPublicInputsHash: Hash{
				NewFieldElementFromString("0"),
				NewFieldElementFromString("0"),
				NewFieldElementFromString("0"),
				NewFieldElementFromString("0"),
			},

			expectedPlonkBetas: []F{
				NewFieldElementFromString("11216469004148781751"),
				NewFieldElementFromString("6201977337075152249"),
			},

			expectedPlonkGammas: []F{
				NewFieldElementFromString("8369751006669847974"),
				NewFieldElementFromString("3610024170884289835"),
			},

			expectedPlonkAlphas: []F{
				NewFieldElementFromString("970160439138448145"),
				NewFieldElementFromString("2402201283787401921"),
			},

			expectedPlonkZeta: QuadraticExtension{
				NewFieldElementFromString("17377750363769967882"),
				NewFieldElementFromString("11921191651424768462"),
			},

			expectedFriAlpha: QuadraticExtension{
				NewFieldElementFromString("16721004555774385479"),
				NewFieldElementFromString("10688151135543754663"),
			},

			expectedFriBetas: []QuadraticExtension{
				{
					NewFieldElementFromString("3312441922957827805"),
					NewFieldElementFromString("15128092514958289671"),
				},
				{
					NewFieldElementFromString("13630530769060141802"),
					NewFieldElementFromString("14559883974933163008"),
				},
				{
					NewFieldElementFromString("16146508250083930687"),
					NewFieldElementFromString("5176346568444408396"),
				},
			},

			expectedFriQueryIndices: []F{
				NewFieldElement(92683),
				NewFieldElement(71707),
				NewFieldElement(113185),
				NewFieldElement(5303),
				NewFieldElement(69637),
				NewFieldElement(52851),
				NewFieldElement(130176),
				NewFieldElement(130602),
				NewFieldElement(17969),
				NewFieldElement(49676),
				NewFieldElement(50573),
				NewFieldElement(73593),
				NewFieldElement(97340),
				NewFieldElement(42687),
				NewFieldElement(66789),
				NewFieldElement(12977),
				NewFieldElement(66752),
				NewFieldElement(28854),
				NewFieldElement(89172),
				NewFieldElement(73873),
				NewFieldElement(66407),
				NewFieldElement(62271),
				NewFieldElement(40881),
				NewFieldElement(130802),
				NewFieldElement(13158),
				NewFieldElement(13338),
				NewFieldElement(8850),
				NewFieldElement(120997),
			},
		}
		witness := TestVerifierCircuit{} // No real witness as the test circuit's Define function will inject in the witness
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
