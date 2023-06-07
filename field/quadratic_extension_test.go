package field

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: ADD MORE TEST CASES!!!

// Test for quadratic extension multiplication
type TestQuadraticExtensionMulCircuit struct {
	qeAPI *QuadraticExtensionAPI

	Operand1       QuadraticExtension
	Operand2       QuadraticExtension
	ExpectedResult QuadraticExtension
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	fieldAPI := NewFieldAPI(api)
	c.qeAPI = NewQuadraticExtensionAPI(api, fieldAPI)

	actualRes := c.qeAPI.MulExtension(c.Operand1, c.Operand2)

	fieldAPI.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	fieldAPI.AssertIsEqual(actualRes[1], c.ExpectedResult[1])

	return nil
}
func TestQuadraticExtensionMul(t *testing.T) {
	assert := test.NewAssert(t)

	operand1 := QuadraticExtension{NewFieldConst(4994088319481652598), NewFieldConst(16489566008211790727)}
	operand2 := QuadraticExtension{NewFieldConst(3797605683985595697), NewFieldConst(13424401189265534004)}
	expectedResult := QuadraticExtension{NewFieldConst(15052319864161058789), NewFieldConst(16841416332519902625)}

	circuit := TestQuadraticExtensionMulCircuit{Operand1: operand1, Operand2: operand2, ExpectedResult: expectedResult}
	witness := TestQuadraticExtensionMulCircuit{Operand1: operand1, Operand2: operand2, ExpectedResult: expectedResult}
	err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
	assert.NoError(err)
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	qeAPI *QuadraticExtensionAPI

	Operand1       QuadraticExtension
	Operand2       QuadraticExtension
	ExpectedResult QuadraticExtension
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	fieldAPI := NewFieldAPI(api)
	c.qeAPI = NewQuadraticExtensionAPI(api, fieldAPI)

	actualRes := c.qeAPI.DivExtension(c.Operand1, c.Operand2)

	fieldAPI.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	fieldAPI.AssertIsEqual(actualRes[1], c.ExpectedResult[1])

	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)

	operand1 := QuadraticExtension{NewFieldConst(4994088319481652598), NewFieldConst(16489566008211790727)}
	operand2 := QuadraticExtension{NewFieldConst(7166004739148609569), NewFieldConst(14655965871663555016)}
	expectedResult := QuadraticExtension{NewFieldConst(15052319864161058789), NewFieldConst(16841416332519902625)}

	circuit := TestQuadraticExtensionDivCircuit{Operand1: operand1, Operand2: operand2, ExpectedResult: expectedResult}
	witness := TestQuadraticExtensionDivCircuit{Operand1: operand1, Operand2: operand2, ExpectedResult: expectedResult}
	err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
	assert.NoError(err)
}
