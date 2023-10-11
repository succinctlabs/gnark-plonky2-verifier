package goldilocks

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
	chip := NewChip(api)
	chip.RangeCheck(NewVariable(c.X))
	return nil
}
func TestGoldilocksRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksRangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = MODULUS
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	one := big.NewInt(1)
	maxValidVal := new(big.Int).Sub(MODULUS, one)
	witness.X = maxValidVal
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type TestGoldilocksMulAddCircuit struct {
	X, Y, Z        frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestGoldilocksMulAddCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	calculateValue := chip.MulAdd(NewVariable(c.X), NewVariable(c.Y), NewVariable(c.Z))
	api.AssertIsEqual(calculateValue.Limb, c.ExpectedResult)
	return nil
}

func TestGoldilocksMulAdd(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksMulAddCircuit

	witness.X = 1
	witness.Y = 2
	witness.Z = 3
	witness.ExpectedResult = 5
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	bigOperand := new(big.Int).SetUint64(9223372036854775808)
	expectedValue, _ := new(big.Int).SetString("18446744068340842500", 10)

	witness.X = bigOperand
	witness.Y = bigOperand
	witness.Z = 3
	witness.ExpectedResult = expectedValue
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
