package fri_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestFriCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`

	plonkZeta       field.QuadraticExtension
	friAlpha        field.QuadraticExtension
	friBetas        []field.QuadraticExtension
	friPOWResponse  field.F
	friQueryIndices []field.F
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := poseidon.NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	friChip := fri.NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)

	friChallenges := common.FriChallenges{
		FriAlpha:        circuit.friAlpha,
		FriBetas:        circuit.friBetas,
		FriPowResponse:  circuit.friPOWResponse,
		FriQueryIndices: circuit.friQueryIndices,
	}

	initialMerkleCaps := []common.MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	friChip.VerifyFriProof(
		fri.GetFriInstance(&commonCircuitData, qeAPI, circuit.plonkZeta, commonCircuitData.DegreeBits),
		fri.ToFriOpenings(proofWithPis.Proof.Openings),
		&friChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)

	return nil
}

func TestFibonacciFriProof(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestFriCircuit{
			proofWithPIsFilename:            "./data/fibonacci/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/fibonacci/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/fibonacci/verifier_only_circuit_data.json",
			plonkZeta: field.QuadraticExtension{
				field.NewFieldElementFromString("14887793628029982930"),
				field.NewFieldElementFromString("1136137158284059037"),
			},
			friAlpha: field.QuadraticExtension{
				field.NewFieldElementFromString("14641715242626918707"),
				field.NewFieldElementFromString("10574243340537902930"),
			},
			friBetas:       []field.QuadraticExtension{},
			friPOWResponse: field.NewFieldElement(82451580476419),
			friQueryIndices: []field.F{
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
		witness := TestFriCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestDummyFriProof(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestFriCircuit{
			proofWithPIsFilename:            "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/dummy_2^14_gates/verifier_only_circuit_data.json",
			plonkZeta: field.QuadraticExtension{
				field.NewFieldElementFromString("17377750363769967882"),
				field.NewFieldElementFromString("11921191651424768462"),
			},
			friAlpha: field.QuadraticExtension{
				field.NewFieldElementFromString("16721004555774385479"),
				field.NewFieldElementFromString("10688151135543754663"),
			},
			friBetas: []field.QuadraticExtension{
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
			friPOWResponse: field.NewFieldElement(4389),
			friQueryIndices: []field.F{
				field.NewFieldElementFromString("16334967868590615051"),
				field.NewFieldElementFromString("2911473540496037915"),
				field.NewFieldElementFromString("14887216056886344225"),
				field.NewFieldElementFromString("7808811227805914295"),
				field.NewFieldElementFromString("2018594961417375749"),
				field.NewFieldElementFromString("3733368398777208435"),
				field.NewFieldElementFromString("2623035669037055104"),
				field.NewFieldElementFromString("299243030573481514"),
				field.NewFieldElementFromString("7189789717962704433"),
				field.NewFieldElementFromString("14566344026886816268"),
				field.NewFieldElementFromString("12555390069003437453"),
				field.NewFieldElementFromString("17225508403199418233"),
				field.NewFieldElementFromString("5088797913879903292"),
				field.NewFieldElementFromString("9715691392773433023"),
				field.NewFieldElementFromString("7565836764713256165"),
				field.NewFieldElementFromString("1500143546029322929"),
				field.NewFieldElementFromString("1245802417104422080"),
				field.NewFieldElementFromString("6831959786661245110"),
				field.NewFieldElementFromString("17271054758535453780"),
				field.NewFieldElementFromString("6225460404576395409"),
				field.NewFieldElementFromString("15932661092896277351"),
				field.NewFieldElementFromString("12452534049198240575"),
				field.NewFieldElementFromString("4225199666055520177"),
				field.NewFieldElementFromString("13235091290587791090"),
				field.NewFieldElementFromString("2562357622728700774"),
				field.NewFieldElementFromString("17676678042980201498"),
				field.NewFieldElementFromString("5837067135702409874"),
				field.NewFieldElementFromString("11238419549114325157"),
			},
		}
		witness := TestFriCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
