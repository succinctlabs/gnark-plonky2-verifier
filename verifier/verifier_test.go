package verifier_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestVerifierChallengesCircuit struct {
	fieldAPI frontend.API                 `gnark:"-"`
	qeAPI    *field.QuadraticExtensionAPI `gnark:"-"`
	hashAPI  *poseidon.HashAPI            `gnark:"-"`

	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`

	numChallenges uint64 `gnark:"-"`
	numFriQueries uint64 `gnark:"-"`

	t *testing.T `gnark:"-"`

	expectedPublicInputsHash poseidon.Hash
	expectedPlonkBetas       []field.F // slice length == num challenges
	expectedPlonkGammas      []field.F // slice length == num challenges
	expectedPlonkAlphas      []field.F // slice length == num challenges
	expectedPlonkZeta        field.QuadraticExtension
	expectedFriAlpha         field.QuadraticExtension
	expectedFriBetas         []field.QuadraticExtension // slice length == num fri rounds
	expectedFriQueryIndices  []field.F                  // slice length == num fri queries

	verifierChip *verifier.VerifierChip
}

func (c *TestVerifierChallengesCircuit) GetChallengesSanityCheck(
	proofWithPis common.ProofWithPublicInputs,
	verifierData common.VerifierOnlyCircuitData,
	commonData common.CommonCircuitData,
) {
	publicInputsHash := c.verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := c.verifierChip.GetChallenges(proofWithPis, publicInputsHash, commonData, verifierData)

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
	// expectedPowResponse := field.NewFieldElementFromString("92909863298412")
	// c.field.AssertIsEqual(proofChallenges.FriChallenges.FriPowResponse, expectedPowResponse)

	if len(proofChallenges.FriChallenges.FriQueryIndices) != int(c.numFriQueries) {
		c.t.Errorf("len(expectedFriQueryIndices) should equal num fri queries")
	}

	for i := 0; i < int(c.numFriQueries); i++ {
		c.fieldAPI.AssertIsEqual(c.expectedFriQueryIndices[i], proofChallenges.FriChallenges.FriQueryIndices[i])
	}
}

func (c *TestVerifierChallengesCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(c.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(c.commonCircuitDataFilename)
	verfierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(c.verifierOnlyCircuitDataFilename)

	c.numChallenges = commonCircuitData.Config.NumChallenges
	c.numFriQueries = commonCircuitData.FriParams.Config.NumQueryRounds

	c.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	c.GetChallengesSanityCheck(proofWithPis, verfierOnlyCircuitData, commonCircuitData)
	return nil
}

func TestFibonacciVerifierWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierChallengesCircuit{
			proofWithPIsFilename:            "./data/fibonacci/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/fibonacci/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/fibonacci/verifier_only_circuit_data.json",
			t:                               t,

			expectedPublicInputsHash: poseidon.Hash{
				field.NewFieldElementFromString("8416658900775745054"),
				field.NewFieldElementFromString("12574228347150446423"),
				field.NewFieldElementFromString("9629056739760131473"),
				field.NewFieldElementFromString("3119289788404190010"),
			},

			expectedPlonkBetas: []field.F{
				field.NewFieldElementFromString("4678728155650926271"),
				field.NewFieldElementFromString("13611962404289024887"),
			},

			expectedPlonkGammas: []field.F{
				field.NewFieldElementFromString("13237663823305715949"),
				field.NewFieldElementFromString("15389314098328235145"),
			},

			expectedPlonkAlphas: []field.F{
				field.NewFieldElementFromString("14505919539124304197"),
				field.NewFieldElementFromString("1695455639263736117"),
			},

			expectedPlonkZeta: field.QuadraticExtension{
				field.NewFieldElementFromString("14887793628029982930"),
				field.NewFieldElementFromString("1136137158284059037"),
			},

			expectedFriAlpha: field.QuadraticExtension{
				field.NewFieldElementFromString("14641715242626918707"),
				field.NewFieldElementFromString("10574243340537902930"),
			},

			expectedFriBetas: []field.QuadraticExtension{},

			expectedFriQueryIndices: []field.F{
				field.NewFieldElement(6790812084677375942),
				field.NewFieldElement(12394212020331474798),
				field.NewFieldElement(16457600747000998582),
				field.NewFieldElement(1543271328932331916),
				field.NewFieldElement(12115726870906958644),
				field.NewFieldElement(6775897107605342797),
				field.NewFieldElement(15989401564746021030),
				field.NewFieldElement(10691676456016926845),
				field.NewFieldElement(1632499470630032007),
				field.NewFieldElement(1317292355445098328),
				field.NewFieldElement(18391440812534384252),
				field.NewFieldElement(17321705613231354333),
				field.NewFieldElement(6176487551308859603),
				field.NewFieldElement(7119835651572002873),
				field.NewFieldElement(3903019169623116693),
				field.NewFieldElement(4886491111111487546),
				field.NewFieldElement(4087641893164620518),
				field.NewFieldElement(13801643080324181364),
				field.NewFieldElement(16993775312274189321),
				field.NewFieldElement(9268202926222765679),
				field.NewFieldElement(10683001302406181735),
				field.NewFieldElement(13359465725531647963),
				field.NewFieldElement(4523327590105620849),
				field.NewFieldElement(4883588003760409588),
				field.NewFieldElement(187699146998097671),
				field.NewFieldElement(14489263557623716717),
				field.NewFieldElement(11748359318238148146),
				field.NewFieldElement(13636347200053048758),
			},
		}
		witness := TestVerifierChallengesCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestDummyVerifierWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierChallengesCircuit{
			proofWithPIsFilename:            "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/dummy_2^14_gates/verifier_only_circuit_data.json",
			t:                               t,

			expectedPublicInputsHash: poseidon.Hash{
				field.NewFieldElementFromString("0"),
				field.NewFieldElementFromString("0"),
				field.NewFieldElementFromString("0"),
				field.NewFieldElementFromString("0"),
			},

			expectedPlonkBetas: []field.F{
				field.NewFieldElementFromString("11216469004148781751"),
				field.NewFieldElementFromString("6201977337075152249"),
			},

			expectedPlonkGammas: []field.F{
				field.NewFieldElementFromString("8369751006669847974"),
				field.NewFieldElementFromString("3610024170884289835"),
			},

			expectedPlonkAlphas: []field.F{
				field.NewFieldElementFromString("970160439138448145"),
				field.NewFieldElementFromString("2402201283787401921"),
			},

			expectedPlonkZeta: field.QuadraticExtension{
				field.NewFieldElementFromString("17377750363769967882"),
				field.NewFieldElementFromString("11921191651424768462"),
			},

			expectedFriAlpha: field.QuadraticExtension{
				field.NewFieldElementFromString("16721004555774385479"),
				field.NewFieldElementFromString("10688151135543754663"),
			},

			expectedFriBetas: []field.QuadraticExtension{
				{
					field.NewFieldElementFromString("3312441922957827805"),
					field.NewFieldElementFromString("15128092514958289671"),
				},
				{
					field.NewFieldElementFromString("13630530769060141802"),
					field.NewFieldElementFromString("14559883974933163008"),
				},
				{
					field.NewFieldElementFromString("16146508250083930687"),
					field.NewFieldElementFromString("5176346568444408396"),
				},
			},

			expectedFriQueryIndices: []field.F{
				field.NewFieldElement(16334967868590615051),
				field.NewFieldElement(2911473540496037915),
				field.NewFieldElement(14887216056886344225),
				field.NewFieldElement(7808811227805914295),
				field.NewFieldElement(2018594961417375749),
				field.NewFieldElement(3733368398777208435),
				field.NewFieldElement(2623035669037055104),
				field.NewFieldElement(299243030573481514),
				field.NewFieldElement(7189789717962704433),
				field.NewFieldElement(14566344026886816268),
				field.NewFieldElement(12555390069003437453),
				field.NewFieldElement(17225508403199418233),
				field.NewFieldElement(5088797913879903292),
				field.NewFieldElement(9715691392773433023),
				field.NewFieldElement(7565836764713256165),
				field.NewFieldElement(1500143546029322929),
				field.NewFieldElement(1245802417104422080),
				field.NewFieldElement(6831959786661245110),
				field.NewFieldElement(17271054758535453780),
				field.NewFieldElement(6225460404576395409),
				field.NewFieldElement(15932661092896277351),
				field.NewFieldElement(12452534049198240575),
				field.NewFieldElement(4225199666055520177),
				field.NewFieldElement(13235091290587791090),
				field.NewFieldElement(2562357622728700774),
				field.NewFieldElement(17676678042980201498),
				field.NewFieldElement(5837067135702409874),
				field.NewFieldElement(11238419549114325157),
			},
		}
		witness := TestVerifierChallengesCircuit{} // No real witness as the test circuit's Define function will inject in the witness
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

type TestVerifierCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`
}

func (c *TestVerifierCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(c.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(c.commonCircuitDataFilename)
	verfierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(c.verifierOnlyCircuitDataFilename)

	verifierChip := verifier.NewVerifierChip(api, commonCircuitData)
	verifierChip.Verify(proofWithPis, verfierOnlyCircuitData, commonCircuitData)
	return nil
}

func TestDummyVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestVerifierCircuit{
			proofWithPIsFilename:            "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/dummy_2^14_gates/verifier_only_circuit_data.json",
		}

		witness := TestVerifierCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}
	testCase()
}
