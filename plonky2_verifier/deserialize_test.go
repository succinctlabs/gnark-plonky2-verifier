package plonky2_verifier

import (
	"fmt"
	"testing"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis := DeserializeProofWithPublicInputs("./data/proof_with_public_inputs.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}

func TestDeserializeCommonCircuitData(t *testing.T) {
	proofWithPis := DeserializeCommonCircuitData("./data/common_circuit_data.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	proofWithPis := DeserializeVerifierOnlyCircuitData("./data/verifier_only_circuit_data.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}
