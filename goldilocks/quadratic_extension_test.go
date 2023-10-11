package goldilocks

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestQuadraticExtensionMulCircuit struct {
	Operand1       QuadraticExtensionVariable
	Operand2       QuadraticExtensionVariable
	ExpectedResult QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	glApi := New(api)
	actualRes := glApi.MulExtension(c.Operand1, c.Operand2)
	glApi.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glApi.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionMul4(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := QuadraticExtensionVariable{
		NewVariable("4994088319481652598"),
		NewVariable("16489566008211790727"),
	}
	operand2 := QuadraticExtensionVariable{
		NewVariable("3797605683985595697"),
		NewVariable("13424401189265534004"),
	}
	expectedResult := QuadraticExtensionVariable{
		NewVariable("15052319864161058789"),
		NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	Operand1       QuadraticExtensionVariable
	Operand2       QuadraticExtensionVariable
	ExpectedResult QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	glAPI := New(api)
	actualRes := glAPI.DivExtension(c.Operand1, c.Operand2)
	glAPI.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glAPI.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := QuadraticExtensionVariable{
		NewVariable("4994088319481652598"),
		NewVariable("16489566008211790727"),
	}
	operand2 := QuadraticExtensionVariable{
		NewVariable("7166004739148609569"),
		NewVariable("14655965871663555016"),
	}
	expectedResult := QuadraticExtensionVariable{
		NewVariable("15052319864161058789"),
		NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
