package main

import (
	"fmt"
	. "gnark-ed25519/field"
	. "gnark-ed25519/plonky2_verifier"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type BenchmarkPlonkCircuit struct {
	proofChallenges ProofChallenges
	openings        OpeningSet
}

func (circuit *BenchmarkPlonkCircuit) Define(api frontend.API) error {
	commonCircuitData := DeserializeCommonCircuitData("./plonky2_verifier/data/dummy_2^14_gates/common_circuit_data.json")

	field := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(field, commonCircuitData.DegreeBits)

	plonkChip := NewPlonkChip(api, qeAPI, commonCircuitData)

	plonkChip.Verify(circuit.proofChallenges, circuit.openings)

	return nil
}

func compileCircuit() frontend.CompiledConstraintSystem {
	fmt.Println("compiling circuit", time.Now())
	circuit := BenchmarkPlonkCircuit{}

	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")

	// Challenge associated with the data from "/.data/dummy_2^14_gates/*"
	proofChallenges := ProofChallenges{
		PlonkBetas: []F{
			NewFieldElementFromString("4678728155650926271"),
			NewFieldElementFromString("13611962404289024887"),
		},
		PlonkGammas: []F{
			NewFieldElementFromString("13237663823305715949"),
			NewFieldElementFromString("15389314098328235145"),
		},
		PlonkAlphas: []F{
			NewFieldElementFromString("14505919539124304197"),
			NewFieldElementFromString("1695455639263736117"),
		},
		PlonkZeta: QuadraticExtension{
			NewFieldElementFromString("14887793628029982930"),
			NewFieldElementFromString("1136137158284059037"),
		},
	}

	circuit.proofChallenges = proofChallenges
	circuit.openings = proofWithPis.Proof.Openings

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	return r1cs
}

func createProof(r1cs frontend.CompiledConstraintSystem) groth16.Proof {
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")

	// Challenge associated with the data from "/.data/dummy_2^14_gates/*"
	proofChallenges := ProofChallenges{
		PlonkBetas: []F{
			NewFieldElementFromString("4678728155650926271"),
			NewFieldElementFromString("13611962404289024887"),
		},
		PlonkGammas: []F{
			NewFieldElementFromString("13237663823305715949"),
			NewFieldElementFromString("15389314098328235145"),
		},
		PlonkAlphas: []F{
			NewFieldElementFromString("14505919539124304197"),
			NewFieldElementFromString("1695455639263736117"),
		},
		PlonkZeta: QuadraticExtension{
			NewFieldElementFromString("14887793628029982930"),
			NewFieldElementFromString("1136137158284059037"),
		},
	}

	// Witness
	assignment := &BenchmarkPlonkCircuit{
		proofChallenges: proofChallenges,
		openings:        proofWithPis.Proof.Openings,
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
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
	fi, _ := os.Open("dummy_fri.r1cs")
	r1cs.WriteTo(fi)
	proof := createProof(r1cs)
	fmt.Println(proof.CurveID(), time.Now())
}
