package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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
	proofChallenges := verifierChip.GetChallenges(proofWithPis.Proof, publicInputsHash, commonCircuitData, verifierOnlyCircuitData)

	plonkChip := plonk.NewPlonkChip(
		api,
		commonCircuitData,
	)

	plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)
	return nil
}

func TestPlonkDecodeBlock(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPIsFilename:            "../../data/decode_block/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "../../data/decode_block/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "../../data/decode_block/verifier_only_circuit_data.json",
		}
		witness := TestPlonkCircuit{}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
