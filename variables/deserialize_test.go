package variables

import (
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis := DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/decode_block/proof_with_public_inputs.json"))
	t.Logf("%+v\n", proofWithPis)
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/decode_block/verifier_only_circuit_data.json"))
	t.Logf("%+v\n", verifierOnlyCircuitData)
}
