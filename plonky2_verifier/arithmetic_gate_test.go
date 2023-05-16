package plonky2_verifier

import (
	"errors"
	"fmt"
	. "gnark-plonky2-verifier/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestArithmeticGateCircuit struct{}

func (circuit *TestArithmeticGateCircuit) Define(api frontend.API) error {
	commonCircuitData := DeserializeCommonCircuitData("./data/step/common_circuit_data.json")
	numSelectors := len(commonCircuitData.SelectorsInfo.groups)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	arithmeticGate := ArithmeticGate{numOps: 20}
	vars := EvaluationVars{localConstants: localConstants[numSelectors:], localWires: localWires, publicInputsHash: publicInputsHash}

	constraints := arithmeticGate.EvalUnfiltered(plonkChip, vars)

	if len(constraints) != len(arithmeticGateExpectedConstraints) {
		return errors.New("arithmetic gate constraints length mismatch")
	}

	for i := 0; i < len(constraints); i++ {
		fmt.Printf("constraints[%d] = %v\n", i, constraints[i])
	}

	for i := 0; i < len(constraints); i++ {
		qeAPI.AssertIsEqual(constraints[i], arithmeticGateExpectedConstraints[i])
	}

	return nil
}

func TestArithmeticGate(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestArithmeticGateCircuit{}
		witness := TestArithmeticGateCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
