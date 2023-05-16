package plonky2_verifier

import (
	"errors"
	"fmt"
	. "gnark-plonky2-verifier/field"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestRandomAccessGateCircuit struct{}

func (circuit *TestRandomAccessGateCircuit) Define(api frontend.API) error {
	commonCircuitData := DeserializeCommonCircuitData("./data/step/common_circuit_data.json")
	numSelectors := len(commonCircuitData.SelectorsInfo.groups)

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	randomAccessGate := RandomAccessGate{bits: 4, numCopies: 4, numExtraConstants: 2}
	vars := EvaluationVars{localConstants: localConstants[numSelectors:], localWires: localWires, publicInputsHash: publicInputsHash}

	constraints := randomAccessGate.EvalUnfiltered(plonkChip, vars)

	if len(constraints) != len(randomAccessGateExpectedConstraints) {
		return errors.New("constant gate constraints length mismatch")
	}

	for i := 0; i < len(constraints); i++ {
		fmt.Printf("constraint[%d]: %v\n", i, constraints[i])
	}

	for i := 0; i < len(constraints); i++ {
		qeAPI.AssertIsEqual(constraints[i], constantGateExpectedConstraints[i])
	}

	return nil
}

func TestRandomAccessGate(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestRandomAccessGateCircuit{}
		witness := TestRandomAccessGateCircuit{}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
