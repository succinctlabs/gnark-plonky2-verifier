package plonky2_verifier

import (
	"errors"
	. "gnark-plonky2-verifier/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestConstantGateCircuit struct{}

func (circuit *TestConstantGateCircuit) Define(api frontend.API) error {
	commonCircuitData := DeserializeCommonCircuitData("./data/step/common_circuit_data.json")
	numSelectors := len(commonCircuitData.SelectorsInfo.groups)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	constantGate := ConstantGate{numConsts: 2}
	vars := EvaluationVars{localConstants: localConstants[numSelectors:], localWires: localWires, publicInputsHash: publicInputsHash}

	constraints := constantGate.EvalUnfiltered(plonkChip, vars)

	if len(constraints) != len(constantGateExpectedConstraints) {
		return errors.New("constant gate constraints length mismatch")
	}

	for i := 0; i < len(constraints); i++ {
		qeAPI.AssertIsEqual(constraints[i], constantGateExpectedConstraints[i])
	}

	return nil
}

func TestConstantGate(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestConstantGateCircuit{}
		witness := TestConstantGateCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
