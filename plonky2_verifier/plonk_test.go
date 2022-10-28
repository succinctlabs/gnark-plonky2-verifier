package plonky2_verifier

import (
	. "gnark-ed25519/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPlonkCircuit struct{}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs("./data/fibonacci/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./data/fibonacci/common_circuit_data.json")

	field := NewFieldAPI(api)
	qe := NewQuadraticExtensionAPI(field, commonCircuitData.DegreeBits)

	// Challenge associated with the data from "/.data/fibonacci/*"
	proofChallenges := ProofChallenges{
		PlonkBetas: []F{
			NewFieldElementFromString("4678728155650926271"),
			NewFieldElementFromString("13611962404289024887"),
		},
		PlonkGammas: []F{
			NewFieldElementFromString("13237663823305715949"),
			NewFieldElementFromString("15389314098328235145"),
		},
		PlonkAlphas: []F{
			NewFieldElementFromString("14505919539124304197"),
			NewFieldElementFromString("1695455639263736117"),
		},
		PlonkZeta: QuadraticExtension{
			NewFieldElementFromString("14887793628029982930"),
			NewFieldElementFromString("1136137158284059037"),
		},
	}

	plonkChip := PlonkChip{
		api:             api,
		field:           field,
		qe:              qe,
		commonData:      commonCircuitData,
		proofChallenges: proofChallenges,
		openings:        proofWithPis.Proof.Openings,
	}

	plonkChip.Verify()
	return nil
}

func TestPlonkWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
