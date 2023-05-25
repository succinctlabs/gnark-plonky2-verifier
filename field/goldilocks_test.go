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

type TestQuotientRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestQuotientRangeCheckCircuit) Define(api frontend.API) error {
	QuotientRangeCheck(api, c.X)
	return nil
}
func TestQuotientRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestQuotientRangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	witness.X, _ = new(big.Int).SetString("1186564023953193351969894564072376490961964393355920015360", 10)
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	witness.X, _ = new(big.Int).SetString("1186564023953193351969894564072376490961964393355920015361", 10)
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}

type TestGoldilocksMulAddCircuit struct {
	X, Y, Z        frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestGoldilocksMulAddCircuit) Define(api frontend.API) error {
	calculateValue := GoldilocksMulAdd(api, c.X, c.Y, c.Z)
	api.AssertIsEqual(calculateValue, c.ExpectedResult)

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

type TestGoldilocksReduceCircuit struct {
	X              frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestGoldilocksReduceCircuit) Define(api frontend.API) error {
	calculateValue := GoldilocksReduce(api, c.X)
	api.AssertIsEqual(calculateValue, c.ExpectedResult)

	return nil
}

func TestGoldilocksReduce(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksReduceCircuit

	witness.X = 1
	witness.ExpectedResult = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	witness.X, _ = new(big.Int).SetString("85070591730234615865843651857942052867", 10)
	witness.ExpectedResult, _ = new(big.Int).SetString("18446744068340842500", 10)
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
