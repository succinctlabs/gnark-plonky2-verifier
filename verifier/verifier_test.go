package verifier_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

type TestVerifierCircuit struct {
	Proof        types.Proof
	PublicInputs []gl.Variable `gnark:",public"`

	verifierChip       *verifier.VerifierChip `gnark:"-"`
	plonky2CircuitName string                 `gnark:"-"`
}

func (c *TestVerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./data/" + c.plonky2CircuitName + "/"
	commonCircuitData := verifier.DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := verifier.DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	c.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	c.verifierChip.Verify(c.Proof, c.PublicInputs, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func TestStepVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		plonky2Circuit := "step"
		proofWithPis := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		circuit := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis.Proof,
			PublicInputs:       proofWithPis.PublicInputs,
		}

		proofWithPis2 := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		witness := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis2.Proof,
			PublicInputs:       proofWithPis2.PublicInputs,
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	testCase()
}

func TestStepVerifier2(t *testing.T) {
	assert := test.NewAssert(t)

	plonky2Circuit := "step"
	proofWithPis := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
	circuit := TestVerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
		Proof:              proofWithPis.Proof,
		PublicInputs:       proofWithPis.PublicInputs,
	}

	proofWithPis2 := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
	witness := TestVerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
		Proof:              proofWithPis2.Proof,
		PublicInputs:       proofWithPis2.PublicInputs,
	}

	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
		test.NoSerialization(),
	)
}

func TestWrapperVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		plonky2Circuit := "wrapper"
		proofWithPis := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		circuit := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis.Proof,
			PublicInputs:       proofWithPis.PublicInputs,
		}

		proofWithPis2 := verifier.DeserializeProofWithPublicInputs("./data/" + plonky2Circuit + "/proof_with_public_inputs.json")
		witness := TestVerifierCircuit{
			plonky2CircuitName: plonky2Circuit,
			Proof:              proofWithPis2.Proof,
			PublicInputs:       proofWithPis2.PublicInputs,
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	testCase()
}

type testCircuit struct {
	Arr      [2]emulated.Element[emulated.Secp256k1Fp]
	Expected emulated.Element[emulated.Secp256k1Fp]
}

func (circuit *testCircuit) Define(api frontend.API) error {
	field, _ := emulated.NewField[emulated.Secp256k1Fp](api)

	mulRes := field.Mul(&circuit.Arr[0], &circuit.Arr[1])
	field.AssertIsEqual(mulRes, &circuit.Expected)

	return nil
}

func TestMain(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit testCircuit

	assert.ProverSucceeded(
		&circuit,
		&testCircuit{
			Arr: [2]emulated.Element[emulated.Secp256k1Fp]{
				emulated.ValueOf[emulated.Secp256k1Fp](42),
				emulated.ValueOf[emulated.Secp256k1Fp](24),
			},
			Expected: emulated.ValueOf[emulated.Secp256k1Fp](1008),
		},
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
		test.NoSerialization(),
	)
}
