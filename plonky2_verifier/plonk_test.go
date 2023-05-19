package plonky2_verifier

import (
	"gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPlonkCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := poseidon.NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	friChip := NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	verifierChip := NewVerifierChip(api, fieldAPI, qeAPI, poseidonChip, plonkChip, friChip)
	publicInputsHash := verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := verifierChip.GetChallenges(proofWithPis, publicInputsHash, commonCircuitData, verifierOnlyCircuitData)

	plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)
	return nil
}

func TestPlonkFibonacci(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPIsFilename:            "./data/fibonacci/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/fibonacci/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/fibonacci/verifier_only_circuit_data.json",
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestPlonkDummy(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPIsFilename:            "./data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "./data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "./data/dummy_2^14_gates/verifier_only_circuit_data.json",
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
