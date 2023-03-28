package main

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	. "gnark-plonky2-verifier/plonky2_verifier"
	"gnark-plonky2-verifier/poseidon"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type BenchmarkPlonky2VerifierCircuit struct {
	proofWithPis ProofWithPublicInputs

	verifierChip *VerifierChip
}

func (circuit *BenchmarkPlonky2VerifierCircuit) Define(api frontend.API) error {
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData("./plonky2_verifier/data/dummy_2^14_gates/common_circuit_data.json")
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./plonky2_verifier/data/dummy_2^14_gates/verifier_only_circuit_data.json")

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI)
	friChip := NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)
	circuit.verifierChip = NewVerifierChip(api, fieldAPI, qeAPI, poseidonChip, plonkChip, friChip)

	circuit.verifierChip.Verify(proofWithPis, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func compileCircuit() frontend.CompiledConstraintSystem {
	circuit := BenchmarkPlonky2VerifierCircuit{}
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")
	circuit.proofWithPis = proofWithPis

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	return r1cs
}

func createProof(r1cs frontend.CompiledConstraintSystem) groth16.Proof {
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")

	// Witness
	assignment := &BenchmarkPlonky2VerifierCircuit{
		proofWithPis: proofWithPis,
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	fmt.Println("Running circuit setup", time.Now())
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return proof
}

func main() {
	r1cs := compileCircuit()
	proof := createProof(r1cs)
	fmt.Println(proof.CurveID(), time.Now())
}
