package plonky2_verifier

import (
	"fmt"
	"testing"
)

func TestDeserializeProofWithPublicInputs(t *testing.T) {
	proofWithPis := DeserializeProofWithPublicInputs("./fibonacci_proof.json")
	fmt.Printf("%+v\n", proofWithPis)
	panic("look at stdout")
}
