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

	field := NewFieldAPI(api)
	qe := NewQuadraticExtensionAPI(field, commonCircuitData.DegreeBits)

	proofChallenges := ProofChallenges{
		PlonkBetas:  circuit.plonkBetas,
		PlonkGammas: circuit.plonkGammas,
		PlonkAlphas: circuit.plonkAlphas,
		PlonkZeta:   circuit.plonkZeta,
	}

	plonkChip := NewPlonkChip(api, qe, commonCircuitData)

	poseidonChip := poseidon.NewPoseidonChip(api, field)
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
				NewFieldElementFromString("4678728155650926271"),
				NewFieldElementFromString("13611962404289024887"),
			},
			plonkGammas: []F{
				NewFieldElementFromString("13237663823305715949"),
				NewFieldElementFromString("15389314098328235145"),
			},
			plonkAlphas: []F{
				NewFieldElementFromString("14505919539124304197"),
				NewFieldElementFromString("1695455639263736117"),
			},
			plonkZeta: QuadraticExtension{
				NewFieldElementFromString("14887793628029982930"),
				NewFieldElementFromString("1136137158284059037"),
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
