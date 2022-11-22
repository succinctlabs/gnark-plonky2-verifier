package plonky2_verifier

import (
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestFriCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`

	plonkZeta       QuadraticExtension
	friAlpha        QuadraticExtension
	friBetas        []QuadraticExtension
	friPOWResponse  F
	friQueryIndices []F
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI)
	friChip := NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)

	friChallenges := FriChallenges{
		FriAlpha:         circuit.friAlpha,
		FriBetas:         circuit.friBetas,
		FriPowResponse:   circuit.friPOWResponse,
		FriQueryIndicies: circuit.friQueryIndices,
	}

	initialMerkleCaps := []MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	friChip.VerifyFriProof(
		commonCircuitData.GetFriInstance(qeAPI, circuit.plonkZeta, commonCircuitData.DegreeBits),
		proofWithPis.Proof.Openings.ToFriOpenings(),
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
			plonkZeta: QuadraticExtension{
				NewFieldElementFromString("14887793628029982930"),
				NewFieldElementFromString("1136137158284059037"),
			},
			friAlpha: QuadraticExtension{
				NewFieldElementFromString("14641715242626918707"),
				NewFieldElementFromString("10574243340537902930"),
			},
			friBetas:       []QuadraticExtension{},
			friPOWResponse: NewFieldElement(82451580476419),
			friQueryIndices: []F{
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
		witness := TestFriCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
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
			plonkZeta: QuadraticExtension{
				NewFieldElementFromString("17377750363769967882"),
				NewFieldElementFromString("11921191651424768462"),
			},
			friAlpha: QuadraticExtension{
				NewFieldElementFromString("16721004555774385479"),
				NewFieldElementFromString("10688151135543754663"),
			},
			friBetas: []QuadraticExtension{
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
			friPOWResponse: NewFieldElement(4389),
			friQueryIndices: []F{
				NewFieldElementFromString("16334967868590615051"),
				NewFieldElementFromString("2911473540496037915"),
				NewFieldElementFromString("14887216056886344225"),
				NewFieldElementFromString("7808811227805914295"),
				NewFieldElementFromString("2018594961417375749"),
				NewFieldElementFromString("3733368398777208435"),
				NewFieldElementFromString("2623035669037055104"),
				NewFieldElementFromString("299243030573481514"),
				NewFieldElementFromString("7189789717962704433"),
				NewFieldElementFromString("14566344026886816268"),
				NewFieldElementFromString("12555390069003437453"),
				NewFieldElementFromString("17225508403199418233"),
				NewFieldElementFromString("5088797913879903292"),
				NewFieldElementFromString("9715691392773433023"),
				NewFieldElementFromString("7565836764713256165"),
				NewFieldElementFromString("1500143546029322929"),
				NewFieldElementFromString("1245802417104422080"),
				NewFieldElementFromString("6831959786661245110"),
				NewFieldElementFromString("17271054758535453780"),
				NewFieldElementFromString("6225460404576395409"),
				NewFieldElementFromString("15932661092896277351"),
				NewFieldElementFromString("12452534049198240575"),
				NewFieldElementFromString("4225199666055520177"),
				NewFieldElementFromString("13235091290587791090"),
				NewFieldElementFromString("2562357622728700774"),
				NewFieldElementFromString("17676678042980201498"),
				NewFieldElementFromString("5837067135702409874"),
				NewFieldElementFromString("11238419549114325157"),
			},
		}
		witness := TestFriCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
