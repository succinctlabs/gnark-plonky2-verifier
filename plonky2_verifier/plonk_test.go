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
	proofChallengesFilename   string `gnark:"-"`
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	proofChallenges := DeserializeProofChallenges(circuit.proofChallengesFilename)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)

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
			proofChallengesFilename:   "./data/fibonacci/proof_challenges.json",
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
			proofChallengesFilename:   "./data/dummy_2^14_gates/proof_challenges.json",
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
