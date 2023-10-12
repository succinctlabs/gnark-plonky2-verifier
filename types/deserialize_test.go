package types

import (
	"testing"
)

func TestReadProofWithPublicInputs(t *testing.T) {
	ReadProofWithPublicInputs("../testdata/decode_block/proof_with_public_inputs.json")
}

func TestReadVerifierOnlyCircuitData(t *testing.T) {
	ReadVerifierOnlyCircuitData("../testdata/decode_block/verifier_only_circuit_data.json")
}
