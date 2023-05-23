package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type BenchmarkPlonky2VerifierCircuit struct {
	ProofWithPis common.ProofWithPublicInputs `gnark:",public"`

	verifierChip       *verifier.VerifierChip
	plonky2CircuitName string
}

func (circuit *BenchmarkPlonky2VerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./verifier/data/" + circuit.plonky2CircuitName + "/"
	commonCircuitData := utils.DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	circuit.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	circuit.verifierChip.Verify(circuit.ProofWithPis, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func compileCircuit(plonky2Circuit string) frontend.CompiledConstraintSystem {
	circuit := BenchmarkPlonky2VerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
	}
	proofWithPis := utils.DeserializeProofWithPublicInputs("./verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")
	circuit.ProofWithPis = proofWithPis

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	return r1cs
}

func createProof(r1cs frontend.CompiledConstraintSystem, plonky2Circuit string) groth16.Proof {
	proofWithPis := utils.DeserializeProofWithPublicInputs("./verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")

	// Witness
	assignment := &BenchmarkPlonky2VerifierCircuit{
		ProofWithPis: proofWithPis,
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
