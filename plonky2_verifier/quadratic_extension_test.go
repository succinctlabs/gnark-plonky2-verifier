package plonky2_verifier

import (
	"gnark-plonky2-verifier/field"
	. "gnark-plonky2-verifier/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: ADD MORE TEST CASES!!!

// Test for quadratic extension multiplication
type TestQuadraticExtensionMulCircuit struct {
	qeAPI *QuadraticExtensionAPI

	operand1       QuadraticExtension
	operand2       QuadraticExtension
	expectedResult QuadraticExtension
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	field := field.NewFieldAPI(api)
	degreeBits := 3
	c.qeAPI = NewQuadraticExtensionAPI(field, uint64(degreeBits))

	actualRes := c.qeAPI.MulExtension(c.operand1, c.operand2)

	field.AssertIsEqual(actualRes[0], c.expectedResult[0])
	field.AssertIsEqual(actualRes[1], c.expectedResult[1])

	return nil
}
func TestQuadraticExtensionMul(t *testing.T) {
	assert := test.NewAssert(t)

	operand1 := QuadraticExtension{NewFieldElement(4994088319481652598), NewFieldElement(16489566008211790727)}
	operand2 := QuadraticExtension{NewFieldElement(3797605683985595697), NewFieldElement(13424401189265534004)}
	expectedResult := QuadraticExtension{NewFieldElement(15052319864161058789), NewFieldElement(16841416332519902625)}

	circuit := TestQuadraticExtensionMulCircuit{operand1: operand1, operand2: operand2, expectedResult: expectedResult}
	witness := TestQuadraticExtensionMulCircuit{operand1: operand1, operand2: operand2, expectedResult: expectedResult}
	err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
	assert.NoError(err)
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	qeAPI *QuadraticExtensionAPI

	operand1       QuadraticExtension
	operand2       QuadraticExtension
	expectedResult QuadraticExtension
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	field := field.NewFieldAPI(api)
	degreeBits := 3
	c.qeAPI = NewQuadraticExtensionAPI(field, uint64(degreeBits))

	actualRes := c.qeAPI.DivExtension(c.operand1, c.operand2)

	field.AssertIsEqual(actualRes[0], c.expectedResult[0])
	field.AssertIsEqual(actualRes[1], c.expectedResult[1])

	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)

	operand1 := QuadraticExtension{NewFieldElement(4994088319481652598), NewFieldElement(16489566008211790727)}
	operand2 := QuadraticExtension{NewFieldElement(7166004739148609569), NewFieldElement(14655965871663555016)}
	expectedResult := QuadraticExtension{NewFieldElement(15052319864161058789), NewFieldElement(16841416332519902625)}

	circuit := TestQuadraticExtensionDivCircuit{operand1: operand1, operand2: operand2, expectedResult: expectedResult}
	witness := TestQuadraticExtensionDivCircuit{operand1: operand1, operand2: operand2, expectedResult: expectedResult}
	err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
	assert.NoError(err)
}
