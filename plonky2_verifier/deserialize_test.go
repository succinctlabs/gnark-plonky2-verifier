package plonky2_verifier

import (
	"fmt"
	"testing"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis := DeserializeProofWithPublicInputs("./data/fibonacci/proof_with_public_inputs.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}

func TestDeserializeCommonCircuitData(t *testing.T) {
	commonCircuitData := DeserializeCommonCircuitData("./data/fibonacci/common_circuit_data.json")
	fmt.Printf("%+v\n", commonCircuitData)
	panic("look at stdout")
}

func TestDeserializeVerifierOnlyCircuitData(t *testing.T) {
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./data/fibonacci/verifier_only_circuit_data.json")
	fmt.Printf("%+v\n", verifierOnlyCircuitData)
	panic("look at stdout")
}

func TestDeserializeProofChallenges(t *testing.T) {
	challenges := DeserializeProofChallenges("./data/fibonacci/proof_challenges.json")
	fmt.Printf("%+v\n", challenges)
	panic("look at stdout")
}
