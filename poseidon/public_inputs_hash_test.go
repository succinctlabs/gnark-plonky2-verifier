package poseidon

import (
	. "gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var testCurve = ecc.BN254

type TestPublicInputsHashCircuit struct {
	In  [3]frontend.Variable
	Out [4]frontend.Variable
}

func (circuit *TestPublicInputsHashCircuit) Define(api frontend.API) error {
	fieldAPI := NewFieldAPI(api)

	// BN254 -> Binary(64) -> F
	var input [3]F
	for i := 0; i < 3; i++ {
		input[i] = fieldAPI.FromBinary(api.ToBinary(circuit.In[i], 64)).(F)
	}

	poseidonChip := &PoseidonChip{api: api, fieldAPI: fieldAPI}
	output := poseidonChip.HashNoPad(input[:])

	// Check that output is correct
	for i := 0; i < 4; i++ {
		fieldAPI.AssertIsEqual(
			output[i],
			fieldAPI.FromBinary(api.ToBinary(circuit.Out[i])).(F),
		)
	}

	return nil
}

func TestPublicInputsHashWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [3]frontend.Variable, out [4]frontend.Variable) {
		circuit := TestPublicInputsHashCircuit{In: in, Out: out}
		witness := TestPublicInputsHashCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"0", "1", "3736710860384812976"}
	outStr := []string{"8416658900775745054", "12574228347150446423", "9629056739760131473", "3119289788404190010"}
	var in [3]frontend.Variable
	var out [4]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}
