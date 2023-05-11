package poseidon

import (
	"gnark-plonky2-verifier/field"
	. "gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPoseidonCircuit struct {
	In  [12]frontend.Variable
	Out [12]frontend.Variable
}

func (circuit *TestPoseidonCircuit) Define(api frontend.API) error {
	fieldAPI := field.NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(api, fieldAPI, 3)

	var input PoseidonState
	for i := 0; i < 12; i++ {
		input[i] = fieldAPI.FromBits(api.ToBinary(circuit.In[i], 64)...)
	}

	poseidonChip := NewPoseidonChip(api, fieldAPI, qeAPI)
	output := poseidonChip.Poseidon(input)

	for i := 0; i < 12; i++ {
		fieldAPI.AssertIsEqual(
			output[i],
			fieldAPI.FromBits(api.ToBinary(circuit.Out[i], 64)...),
		)
	}

	return nil
}

func TestPoseidonWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [12]frontend.Variable, out [12]frontend.Variable) {
		circuit := TestPoseidonCircuit{In: in, Out: out}
		witness := TestPoseidonCircuit{In: in, Out: out}
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
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

type TestBitsCircuit struct {
	Inputs0 FTarget
	Inputs1 FTarget
	Inputs2 FTarget
	Inputs3 FTarget
}

func (circuit *TestBitsCircuit) Define(api frontend.API) error {
	fieldAPI := field.NewFieldAPI(api)

	var buffer [4]*FTarget

	buffer[0] = fieldAPI.FromBits(fieldAPI.ToBits(&circuit.Inputs0)...)
	buffer[1] = fieldAPI.FromBits(fieldAPI.ToBits(&circuit.Inputs1)...)
	buffer[2] = fieldAPI.FromBits(fieldAPI.ToBits(&circuit.Inputs2)...)
	buffer[3] = fieldAPI.FromBits(fieldAPI.ToBits(&circuit.Inputs3)...)

	fieldAPI.AssertIsEqual(&circuit.Inputs0, fieldAPI.FromBits(fieldAPI.ToBits(buffer[0])...))
	fieldAPI.AssertIsEqual(&circuit.Inputs1, fieldAPI.FromBits(fieldAPI.ToBits(buffer[1])...))
	fieldAPI.AssertIsEqual(&circuit.Inputs2, fieldAPI.FromBits(fieldAPI.ToBits(buffer[2])...))
	fieldAPI.AssertIsEqual(&circuit.Inputs3, fieldAPI.FromBits(fieldAPI.ToBits(buffer[3])...))

	return nil
}

func TestBits(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [12]FTarget) {
		var circuit TestBitsCircuit
		witness := TestBitsCircuit{
			Inputs0: in[0],
			Inputs1: in[1],
			Inputs2: in[2],
			Inputs3: in[3]}
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
	}

	inStr := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := []string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}
	var in [12]FTarget
	var out [12]FTarget
	copy(in[:], utils.StrArrayToFieldArray(inStr))
	copy(out[:], utils.StrArrayToFieldArray(outStr))
	testCase(out)
}

/*
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
*/
