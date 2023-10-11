package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

type TestPlonkCircuit struct {
	ProofWithPis            variables.ProofWithPublicInputs   `gnark:",public"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:",public"`
	CommonCircuitData       types.CommonCircuitData
}

func (circuit *TestPlonkCircuit) Define(api frontend.API) error {
	commonCircuitData := circuit.CommonCircuitData
	verifierOnlyCircuitData := circuit.VerifierOnlyCircuitData
	proofWithPis := circuit.ProofWithPis

	verifierChip := verifier.NewVerifierChip(api, commonCircuitData)
	publicInputsHash := verifierChip.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := verifierChip.GetChallenges(proofWithPis.Proof, publicInputsHash, verifierOnlyCircuitData)

	plonkChip := plonk.NewPlonkChip(
		api,
		commonCircuitData,
	)

	plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)
	return nil
}

func TestPlonkDecodeBlock(t *testing.T) {
	assert := test.NewAssert(t)

	proofWithPIsFilename := "../testdata/decode_block/proof_with_public_inputs.json"
	commonCircuitDataFilename := "../testdata/decode_block/common_circuit_data.json"
	verifierOnlyCircuitDataFilename := "../testdata/decode_block/verifier_only_circuit_data.json"

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(proofWithPIsFilename))
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataFilename)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(verifierOnlyCircuitDataFilename))

	testCase := func() {
		circuit := TestPlonkCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		witness := TestPlonkCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
