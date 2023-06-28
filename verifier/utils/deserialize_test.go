package utils

import (
	"fmt"
	"testing"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis := DeserializeProofWithPublicInputsFromFile("../data/decode_block/proof_with_public_inputs.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}

func TestDeserializeCommonCircuitData(t *testing.T) {
	commonCircuitData := DeserializeCommonCircuitData("../data/decode_block/common_circuit_data.json")
	fmt.Printf("%+v\n", commonCircuitData)
	panic("look at stdout")
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("../data/decode_block/verifier_only_circuit_data.json")
	fmt.Printf("%+v\n", verifierOnlyCircuitData)
	panic("look at stdout")
}
