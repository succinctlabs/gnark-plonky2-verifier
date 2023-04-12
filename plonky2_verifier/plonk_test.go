package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPlonkCircuit struct {
	proofWithPIsFilename      string `gnark:"-"`
	commonCircuitDataFilename string `gnark:"-"`

	plonkBetas  []F
	plonkGammas []F
	plonkAlphas []F
	plonkZeta   QuadraticExtension
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)

	proofChallenges := ProofChallenges{
		PlonkBetas:  circuit.plonkBetas,
		PlonkGammas: circuit.plonkGammas,
		PlonkAlphas: circuit.plonkAlphas,
		PlonkZeta:   circuit.plonkZeta,
	}

	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	publicInputsHash := poseidonChip.HashNoPad(proofWithPis.PublicInputs)

	plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)
	return nil
}

func TestPlonkFibonacci(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPIsFilename:      "./data/fibonacci/proof_with_public_inputs.json",
			commonCircuitDataFilename: "./data/fibonacci/common_circuit_data.json",

			plonkBetas: []F{
				NewFieldElementFromString("12973916988745913043"),
				NewFieldElementFromString("10729509799707823061"),
			},
			plonkGammas: []F{
				NewFieldElementFromString("13357786390712427342"),
				NewFieldElementFromString("13733012568509939467"),
			},
			plonkAlphas: []F{
				NewFieldElementFromString("4421334860622890213"),
				NewFieldElementFromString("11104346062293008527"),
			},
			plonkZeta: QuadraticExtension{
				NewFieldElementFromString("18168831211174576204"),
				NewFieldElementFromString("14207073590853934065"),
			},
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestPlonkDummy(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPIsFilename:      "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename: "./data/dummy_2^14_gates/common_circuit_data.json",

			plonkBetas: []F{
				NewFieldElementFromString("11216469004148781751"),
				NewFieldElementFromString("6201977337075152249"),
			},
			plonkGammas: []F{
				NewFieldElementFromString("8369751006669847974"),
				NewFieldElementFromString("3610024170884289835"),
			},
			plonkAlphas: []F{
				NewFieldElementFromString("970160439138448145"),
				NewFieldElementFromString("2402201283787401921"),
			},
			plonkZeta: QuadraticExtension{
				NewFieldElementFromString("17377750363769967882"),
				NewFieldElementFromString("11921191651424768462"),
			},
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
