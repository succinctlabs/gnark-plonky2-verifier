package plonk_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/plonk"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestPlonkCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	verifierChip := verifier.NewVerifierChip(api, commonCircuitData)
	publicInputsHash := verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := verifierChip.GetChallenges(proofWithPis, publicInputsHash, commonCircuitData, verifierOnlyCircuitData)

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	plonkChip := plonk.NewPlonkChip(
		api,
		qeAPI,
		commonCircuitData,
	)

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
