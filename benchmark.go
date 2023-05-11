package main

import (
	"flag"
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

	verifierChip       *VerifierChip
	plonky2CircuitName string
}

func (circuit *BenchmarkPlonky2VerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./plonky2_verifier/data/" + circuit.plonky2CircuitName + "/"
	proofWithPis := DeserializeProofWithPublicInputs(circuitDirname + "proof_with_public_inputs.json")
	commonCircuitData := DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	fieldAPI := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	friChip := NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)
	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)
	circuit.verifierChip = NewVerifierChip(api, fieldAPI, qeAPI, poseidonChip, plonkChip, friChip)

	circuit.verifierChip.Verify(proofWithPis, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func compileCircuit(plonky2Circuit string) frontend.CompiledConstraintSystem {
	circuit := BenchmarkPlonky2VerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
	}
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")
	circuit.proofWithPis = proofWithPis

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	return r1cs
}

func createProof(r1cs frontend.CompiledConstraintSystem, plonky2Circuit string) groth16.Proof {
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")

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
	plonky2Circuit := flag.String("plonky2-circuit", "", "plonky2 circuit to benchmark")
	flag.Parse()

	if plonky2Circuit == nil || *plonky2Circuit == "" {
		fmt.Println("Please provide a plonky2 circuit to benchmark")
		os.Exit(1)
	}

	r1cs := compileCircuit(*plonky2Circuit)
	proof := createProof(r1cs, *plonky2Circuit)
	fmt.Println(proof.CurveID(), time.Now())
}
