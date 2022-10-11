package poseidon

import (
	"gnark-ed25519/field"
	. "gnark-ed25519/field"
	"gnark-ed25519/utils"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type TestPoseidonCircuit struct {
	In  [12]frontend.Variable
	Out [12]frontend.Variable
}

func (circuit *TestPoseidonCircuit) Define(api frontend.API) error {
	goldilocksApi := field.NewFieldAPI(api)

	var input PoseidonState
	for i := 0; i < 12; i++ {
		input[i] = goldilocksApi.FromBinary(api.ToBinary(circuit.In[i], 64)).(F)
	}

	poseidonChip := NewPoseidonChip(api, goldilocksApi)
	output := poseidonChip.Poseidon(input)

	for i := 0; i < 12; i++ {
		goldilocksApi.AssertIsEqual(
			output[i],
			goldilocksApi.FromBinary(api.ToBinary(circuit.Out[i])).(F),
		)
	}

	return nil
}

func TestPoseidonWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [12]frontend.Variable, out [12]frontend.Variable) {
		circuit := TestPoseidonCircuit{In: in, Out: out}
		witness := TestPoseidonCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := []string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}

func TestPoseidonProof(t *testing.T) {
	inStr := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := []string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))

	circuit := TestPoseidonCircuit{In: in, Out: out}
	assignment := TestPoseidonCircuit{In: in, Out: out}

	r1cs, err := frontend.Compile(TEST_CURVE.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	err = test.IsSolved(&circuit, &assignment, TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
