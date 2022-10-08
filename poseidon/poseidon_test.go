package poseidon

import (
	. "gnark-ed25519/goldilocks"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

var testCurve = ecc.BN254

type TestPoseidonCircuit struct {
	In  [12]frontend.Variable
	Out [12]frontend.Variable
}

func (circuit *TestPoseidonCircuit) Define(api frontend.API) error {
	goldilocksApi := NewGoldilocksAPI(api)

	// BN254 -> Binary(64) -> GoldilocksElement
	var input PoseidonState
	for i := 0; i < 12; i++ {
		input[i] = goldilocksApi.FromBinary(api.ToBinary(circuit.In[i], 64)).(GoldilocksElement)
	}

	output := Poseidon(api, goldilocksApi, input)

	// Check that output is correct
	for i := 0; i < 12; i++ {
		goldilocksApi.AssertIsEqual(
			output[i],
			goldilocksApi.FromBinary(api.ToBinary(circuit.Out[i])).(GoldilocksElement),
		)
	}

	return nil
}

func TestPoseidonWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(inBigInt [12]big.Int, outBigInt [12]big.Int) {
		var in [12]frontend.Variable
		var out [12]frontend.Variable

		for i := 0; i < 12; i++ {
			in[i] = inBigInt[i]
			out[i] = outBigInt[i]
		}

		circuit := TestPoseidonCircuit{In: in, Out: out}
		witness := TestPoseidonCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}

	inStr := [12]string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := [12]string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}

	var inBigInt [12]big.Int
	var outBigInt [12]big.Int

	for i := 0; i < 12; i++ {
		inTmp := new(big.Int)
		inTmp, _ = inTmp.SetString(inStr[i], 10)
		inBigInt[i] = *inTmp

		outTmp := new(big.Int)
		outTmp, _ = outTmp.SetString(outStr[i], 10)
		outBigInt[i] = *outTmp
	}

	testCase(inBigInt, outBigInt)
}

func TestPoseidonProof(t *testing.T) {
	inStr := [12]string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := [12]string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}

	var in [12]frontend.Variable
	var out [12]frontend.Variable

	for i := 0; i < 12; i++ {
		inTmp := new(big.Int)
		inTmp, _ = inTmp.SetString(inStr[i], 10)
		in[i] = *inTmp

		outTmp := new(big.Int)
		outTmp, _ = outTmp.SetString(outStr[i], 10)
		out[i] = *outTmp
	}

	circuit := TestPoseidonCircuit{In: in, Out: out}
	assignment := TestPoseidonCircuit{In: in, Out: out}

	r1cs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, testCurve.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	err = test.IsSolved(&circuit, &assignment, testCurve.ScalarField())
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
