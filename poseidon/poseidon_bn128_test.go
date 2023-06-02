package poseidon

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/utils"
)

type TestPoseidonBN128Circuit struct {
	In  [SPONGE_WIDTH_BN128]frontend.Variable
	Out [SPONGE_WIDTH_BN128]frontend.Variable
}

func (circuit *TestPoseidonBN128Circuit) Define(api frontend.API) error {
	poseidonChip := NewPoseidonBN128Chip(api)
	output := poseidonChip.Poseidon(circuit.In)

	for i := 0; i < SPONGE_WIDTH_BN128; i++ {
		api.AssertIsEqual(
			output[i],
			circuit.Out[i],
		)
	}

	return nil
}

func TestPoseidonBN128Witness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [SPONGE_WIDTH_BN128]frontend.Variable, out [SPONGE_WIDTH_BN128]frontend.Variable) {
		circuit := TestPoseidonBN128Circuit{In: in, Out: out}
		witness := TestPoseidonBN128Circuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"0", "0", "0", "0"}
	outStr := []string{
		"5317387130258456662214331362918410991734007599705406860481038345552731150762",
		"17768273200467269691696191901389126520069745877826494955630904743826040320364",
		"19413739268543925182080121099097652227979760828059217876810647045303340666757",
		"3717738800218482999400886888123026296874264026760636028937972004600663725187",
	}
	var in [SPONGE_WIDTH_BN128]frontend.Variable
	var out [SPONGE_WIDTH_BN128]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}

func TestPoseidonBN128Proof(t *testing.T) {
	inStr := []string{"0", "0", "0", "0"}
	outStr := []string{
		"5317387130258456662214331362918410991734007599705406860481038345552731150762",
		"17768273200467269691696191901389126520069745877826494955630904743826040320364",
		"19413739268543925182080121099097652227979760828059217876810647045303340666757",
		"3717738800218482999400886888123026296874264026760636028937972004600663725187",
	}
	var in [SPONGE_WIDTH_BN128]frontend.Variable
	var out [SPONGE_WIDTH_BN128]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))

	circuit := TestPoseidonBN128Circuit{In: in, Out: out}
	assignment := TestPoseidonBN128Circuit{In: in, Out: out}

	r1cs, err := frontend.Compile(field.TEST_CURVE.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, field.TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	err = test.IsSolved(&circuit, &assignment, field.TEST_CURVE.ScalarField())
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
