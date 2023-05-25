package field

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestGoldilocksRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestGoldilocksRangeCheckCircuit) Define(api frontend.API) error {
	GoldilocksRangeCheck(api, c.X)
	return nil
}
func TestGoldilocksRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksRangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())

	witness.X = EmulatedField{}.Modulus()
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())

	one := big.NewInt(1)
	maxValidVal := new(big.Int).Sub(EmulatedField{}.Modulus(), one)
	witness.X = maxValidVal
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
