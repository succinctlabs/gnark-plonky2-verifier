package field

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: ADD MORE TEST CASES!!!

// Test for quadratic extension multiplication
type TestQuadraticExtensionMulCircuit struct {
	Operand1, Operand2, ExpectedResult QETarget
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	fieldAPI := NewFieldAPI(api)
	degreeBits := 3
	qeAPI := NewQuadraticExtensionAPI(api, fieldAPI, uint64(degreeBits))

	actualRes := qeAPI.MulExtension(&c.Operand1, &c.Operand2)

	qeAPI.AssertIsEqual(actualRes, &c.ExpectedResult)

	return nil
}

func TestQuadraticExtensionMul(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit TestQuadraticExtensionMulCircuit

	witness := &TestQuadraticExtensionMulCircuit{
		Operand1:       NewQuadraticExtensionConst(NewFieldConst(4994088319481652598), NewFieldConst(16489566008211790727)),
		Operand2:       NewQuadraticExtensionConst(NewFieldConst(3797605683985595697), NewFieldConst(13424401189265534004)),
		ExpectedResult: NewQuadraticExtensionConst(NewFieldConst(15052319864161058789), NewFieldConst(16841416332519902625)),
	}
	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	Operand1, Operand2, ExpectedResult QETarget
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	fieldAPI := NewFieldAPI(api)
	degreeBits := 3
	qeAPI := NewQuadraticExtensionAPI(api, fieldAPI, uint64(degreeBits))

	actualRes := qeAPI.DivExtension(&c.Operand1, &c.Operand2)
	qeAPI.AssertIsEqual(actualRes, &c.ExpectedResult)

	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit TestQuadraticExtensionDivCircuit

	witness := &TestQuadraticExtensionDivCircuit{
		Operand1:       NewQuadraticExtensionConst(NewFieldConst(4994088319481652598), NewFieldConst(16489566008211790727)),
		Operand2:       NewQuadraticExtensionConst(NewFieldConst(7166004739148609569), NewFieldConst(14655965871663555016)),
		ExpectedResult: NewQuadraticExtensionConst(NewFieldConst(15052319864161058789), NewFieldConst(16841416332519902625)),
	}

	assert.ProverSucceeded(&circuit, witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}
