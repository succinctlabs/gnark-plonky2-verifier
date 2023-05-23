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

	PlonkZeta       field.QuadraticExtension
	FriAlpha        field.QuadraticExtension
	FriBetas        []field.QuadraticExtension
	FriPOWResponse  field.F
	FriQueryIndices []field.F
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(api, fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := poseidon.NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	friChip := fri.NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)

	friChallenges := common.FriChallenges{
		FriAlpha:        circuit.FriAlpha,
		FriBetas:        circuit.FriBetas,
		FriPowResponse:  circuit.FriPOWResponse,
		FriQueryIndices: circuit.FriQueryIndices,
	}

	initialMerkleCaps := []common.MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	friChip.VerifyFriProof(
		fri.GetFriInstance(&commonCircuitData, qeAPI, circuit.PlonkZeta, commonCircuitData.DegreeBits),
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
			PlonkZeta: field.QuadraticExtension{
				*field.NewFieldConstFromString("14887793628029982930"),
				*field.NewFieldConstFromString("1136137158284059037"),
			},
			FriAlpha: field.QuadraticExtension{
				*field.NewFieldConstFromString("14641715242626918707"),
				*field.NewFieldConstFromString("10574243340537902930"),
			},
			FriBetas:       []field.QuadraticExtension{},
			FriPOWResponse: *field.NewFieldConst(82451580476419),
			FriQueryIndices: []field.F{
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
			proofWithPIsFilename:            "../../data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "../../data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "../../data/dummy_2^14_gates/verifier_only_circuit_data.json",
			PlonkZeta: field.QuadraticExtension{
				*field.NewFieldConstFromString("17377750363769967882"),
				*field.NewFieldConstFromString("11921191651424768462"),
			},
			FriAlpha: field.QuadraticExtension{
				*field.NewFieldConstFromString("16721004555774385479"),
				*field.NewFieldConstFromString("10688151135543754663"),
			},
			FriBetas: []field.QuadraticExtension{
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
			FriPOWResponse: *field.NewFieldConst(4389),
			FriQueryIndices: []field.F{
				*field.NewFieldConstFromString("16334967868590615051"),
				*field.NewFieldConstFromString("2911473540496037915"),
				*field.NewFieldConstFromString("14887216056886344225"),
				*field.NewFieldConstFromString("7808811227805914295"),
				*field.NewFieldConstFromString("2018594961417375749"),
				*field.NewFieldConstFromString("3733368398777208435"),
				*field.NewFieldConstFromString("2623035669037055104"),
				*field.NewFieldConstFromString("299243030573481514"),
				*field.NewFieldConstFromString("7189789717962704433"),
				*field.NewFieldConstFromString("14566344026886816268"),
				*field.NewFieldConstFromString("12555390069003437453"),
				*field.NewFieldConstFromString("17225508403199418233"),
				*field.NewFieldConstFromString("5088797913879903292"),
				*field.NewFieldConstFromString("9715691392773433023"),
				*field.NewFieldConstFromString("7565836764713256165"),
				*field.NewFieldConstFromString("1500143546029322929"),
				*field.NewFieldConstFromString("1245802417104422080"),
				*field.NewFieldConstFromString("6831959786661245110"),
				*field.NewFieldConstFromString("17271054758535453780"),
				*field.NewFieldConstFromString("6225460404576395409"),
				*field.NewFieldConstFromString("15932661092896277351"),
				*field.NewFieldConstFromString("12452534049198240575"),
				*field.NewFieldConstFromString("4225199666055520177"),
				*field.NewFieldConstFromString("13235091290587791090"),
				*field.NewFieldConstFromString("2562357622728700774"),
				*field.NewFieldConstFromString("17676678042980201498"),
				*field.NewFieldConstFromString("5837067135702409874"),
				*field.NewFieldConstFromString("11238419549114325157"),
			},
		}
		witness := TestFriCircuit{
			proofWithPIsFilename:            "../../data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "../../data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: ".../../data/dummy_2^14_gates/verifier_only_circuit_data.json",
			PlonkZeta: field.QuadraticExtension{
				*field.NewFieldConstFromString("17377750363769967882"),
				*field.NewFieldConstFromString("11921191651424768462"),
			},
			FriAlpha: field.QuadraticExtension{
				*field.NewFieldConstFromString("16721004555774385479"),
				*field.NewFieldConstFromString("10688151135543754663"),
			},
			FriBetas: []field.QuadraticExtension{
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
			FriPOWResponse: *field.NewFieldConst(4389),
			FriQueryIndices: []field.F{
				*field.NewFieldConstFromString("16334967868590615051"),
				*field.NewFieldConstFromString("2911473540496037915"),
				*field.NewFieldConstFromString("14887216056886344225"),
				*field.NewFieldConstFromString("7808811227805914295"),
				*field.NewFieldConstFromString("2018594961417375749"),
				*field.NewFieldConstFromString("3733368398777208435"),
				*field.NewFieldConstFromString("2623035669037055104"),
				*field.NewFieldConstFromString("299243030573481514"),
				*field.NewFieldConstFromString("7189789717962704433"),
				*field.NewFieldConstFromString("14566344026886816268"),
				*field.NewFieldConstFromString("12555390069003437453"),
				*field.NewFieldConstFromString("17225508403199418233"),
				*field.NewFieldConstFromString("5088797913879903292"),
				*field.NewFieldConstFromString("9715691392773433023"),
				*field.NewFieldConstFromString("7565836764713256165"),
				*field.NewFieldConstFromString("1500143546029322929"),
				*field.NewFieldConstFromString("1245802417104422080"),
				*field.NewFieldConstFromString("6831959786661245110"),
				*field.NewFieldConstFromString("17271054758535453780"),
				*field.NewFieldConstFromString("6225460404576395409"),
				*field.NewFieldConstFromString("15932661092896277351"),
				*field.NewFieldConstFromString("12452534049198240575"),
				*field.NewFieldConstFromString("4225199666055520177"),
				*field.NewFieldConstFromString("13235091290587791090"),
				*field.NewFieldConstFromString("2562357622728700774"),
				*field.NewFieldConstFromString("17676678042980201498"),
				*field.NewFieldConstFromString("5837067135702409874"),
				*field.NewFieldConstFromString("11238419549114325157"),
			},
		}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
