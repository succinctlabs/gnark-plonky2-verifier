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
	// expectedPowResponse := *field.NewFieldConstFromString("92909863298412")
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
				*field.NewFieldConstFromString("8416658900775745054"),
				*field.NewFieldConstFromString("12574228347150446423"),
				*field.NewFieldConstFromString("9629056739760131473"),
				*field.NewFieldConstFromString("3119289788404190010"),
			},

			expectedPlonkBetas: []field.F{
				*field.NewFieldConstFromString("4678728155650926271"),
				*field.NewFieldConstFromString("13611962404289024887"),
			},

			expectedPlonkGammas: []field.F{
				*field.NewFieldConstFromString("13237663823305715949"),
				*field.NewFieldConstFromString("15389314098328235145"),
			},

			expectedPlonkAlphas: []field.F{
				*field.NewFieldConstFromString("14505919539124304197"),
				*field.NewFieldConstFromString("1695455639263736117"),
			},

			expectedPlonkZeta: field.QuadraticExtension{
				*field.NewFieldConstFromString("14887793628029982930"),
				*field.NewFieldConstFromString("1136137158284059037"),
			},

			expectedFriAlpha: field.QuadraticExtension{
				*field.NewFieldConstFromString("14641715242626918707"),
				*field.NewFieldConstFromString("10574243340537902930"),
			},

			expectedFriBetas: []field.QuadraticExtension{},

			expectedFriQueryIndices: []field.F{
				*field.NewFieldConst(6790812084677375942),
				*field.NewFieldConst(12394212020331474798),
				*field.NewFieldConst(16457600747000998582),
				*field.NewFieldConst(1543271328932331916),
				*field.NewFieldConst(12115726870906958644),
				*field.NewFieldConst(6775897107605342797),
				*field.NewFieldConst(15989401564746021030),
				*field.NewFieldConst(10691676456016926845),
				*field.NewFieldConst(1632499470630032007),
				*field.NewFieldConst(1317292355445098328),
				*field.NewFieldConst(18391440812534384252),
				*field.NewFieldConst(17321705613231354333),
				*field.NewFieldConst(6176487551308859603),
				*field.NewFieldConst(7119835651572002873),
				*field.NewFieldConst(3903019169623116693),
				*field.NewFieldConst(4886491111111487546),
				*field.NewFieldConst(4087641893164620518),
				*field.NewFieldConst(13801643080324181364),
				*field.NewFieldConst(16993775312274189321),
				*field.NewFieldConst(9268202926222765679),
				*field.NewFieldConst(10683001302406181735),
				*field.NewFieldConst(13359465725531647963),
				*field.NewFieldConst(4523327590105620849),
				*field.NewFieldConst(4883588003760409588),
				*field.NewFieldConst(187699146998097671),
				*field.NewFieldConst(14489263557623716717),
				*field.NewFieldConst(11748359318238148146),
				*field.NewFieldConst(13636347200053048758),
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
				*field.NewFieldConstFromString("0"),
				*field.NewFieldConstFromString("0"),
				*field.NewFieldConstFromString("0"),
				*field.NewFieldConstFromString("0"),
			},

			expectedPlonkBetas: []field.F{
				*field.NewFieldConstFromString("11216469004148781751"),
				*field.NewFieldConstFromString("6201977337075152249"),
			},

			expectedPlonkGammas: []field.F{
				*field.NewFieldConstFromString("8369751006669847974"),
				*field.NewFieldConstFromString("3610024170884289835"),
			},

			expectedPlonkAlphas: []field.F{
				*field.NewFieldConstFromString("970160439138448145"),
				*field.NewFieldConstFromString("2402201283787401921"),
			},

			expectedPlonkZeta: field.QuadraticExtension{
				*field.NewFieldConstFromString("17377750363769967882"),
				*field.NewFieldConstFromString("11921191651424768462"),
			},

			expectedFriAlpha: field.QuadraticExtension{
				*field.NewFieldConstFromString("16721004555774385479"),
				*field.NewFieldConstFromString("10688151135543754663"),
			},

			expectedFriBetas: []field.QuadraticExtension{
				{
					*field.NewFieldConstFromString("3312441922957827805"),
					*field.NewFieldConstFromString("15128092514958289671"),
				},
				{
					*field.NewFieldConstFromString("13630530769060141802"),
					*field.NewFieldConstFromString("14559883974933163008"),
				},
				{
					*field.NewFieldConstFromString("16146508250083930687"),
					*field.NewFieldConstFromString("5176346568444408396"),
				},
			},

			expectedFriQueryIndices: []field.F{
				*field.NewFieldConst(16334967868590615051),
				*field.NewFieldConst(2911473540496037915),
				*field.NewFieldConst(14887216056886344225),
				*field.NewFieldConst(7808811227805914295),
				*field.NewFieldConst(2018594961417375749),
				*field.NewFieldConst(3733368398777208435),
				*field.NewFieldConst(2623035669037055104),
				*field.NewFieldConst(299243030573481514),
				*field.NewFieldConst(7189789717962704433),
				*field.NewFieldConst(14566344026886816268),
				*field.NewFieldConst(12555390069003437453),
				*field.NewFieldConst(17225508403199418233),
				*field.NewFieldConst(5088797913879903292),
				*field.NewFieldConst(9715691392773433023),
				*field.NewFieldConst(7565836764713256165),
				*field.NewFieldConst(1500143546029322929),
				*field.NewFieldConst(1245802417104422080),
				*field.NewFieldConst(6831959786661245110),
				*field.NewFieldConst(17271054758535453780),
				*field.NewFieldConst(6225460404576395409),
				*field.NewFieldConst(15932661092896277351),
				*field.NewFieldConst(12452534049198240575),
				*field.NewFieldConst(4225199666055520177),
				*field.NewFieldConst(13235091290587791090),
				*field.NewFieldConst(2562357622728700774),
				*field.NewFieldConst(17676678042980201498),
				*field.NewFieldConst(5837067135702409874),
				*field.NewFieldConst(11238419549114325157),
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
