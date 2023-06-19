package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

type BenchmarkPlonky2VerifierCircuit struct {
	Proof        common.Proof
	PublicInputs []field.F `gnark:",public"`

	verifierChip       *verifier.VerifierChip `gnark:"-"`
	plonky2CircuitName string                 `gnark:"-"`
}

func (circuit *BenchmarkPlonky2VerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./verifier/data/" + circuit.plonky2CircuitName + "/"
	commonCircuitData := utils.DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	circuit.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	circuit.verifierChip.Verify(circuit.Proof, circuit.PublicInputs, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func compileCircuit(plonky2Circuit string, profileCircuit bool, serialize bool, outputSolidity bool) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	circuit := BenchmarkPlonky2VerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
	}
	proofWithPis := utils.DeserializeProofWithPublicInputs("./verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")
	circuit.Proof = proofWithPis.Proof
	circuit.PublicInputs = proofWithPis.PublicInputs

	var p *profile.Profile
	if profileCircuit {
		p = profile.Start()
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	// Don't serialize the circuit for now, since it takes up too much memory
	/*
		if serialize {
			fR1CS, _ := os.Create("circuit")
			r1cs.WriteTo(fR1CS)
			fR1CS.Close()
		}
	*/

	fmt.Println("Running circuit setup", time.Now())
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if serialize {
		fPK, _ := os.Create("proving.key")
		pk.WriteTo(fPK)
		fPK.Close()

		fVK, _ := os.Create("verifying.key")
		vk.WriteTo(fVK)
		fVK.Close()
	}

	if outputSolidity {
		fSolidity, _ := os.Create("proof.sol")
		err = vk.ExportSolidity(fSolidity)
	}

	return r1cs, pk, vk
}

func createProof(plonky2Circuit string, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, serialize bool) groth16.Proof {
	proofWithPis := utils.DeserializeProofWithPublicInputs("./verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")

	// Witness
	assignment := &BenchmarkPlonky2VerifierCircuit{
		Proof:        proofWithPis.Proof,
		PublicInputs: proofWithPis.PublicInputs,
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

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

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())

	return proof
}

func main() {
	plonky2Circuit := flag.String("plonky2-circuit", "", "plonky2 circuit to benchmark")
	profileCircuit := flag.Bool("profile", false, "profile the circuit")
	serialize := flag.Bool("serialize", false, "serialize the circuit")
	outputSolidity := flag.Bool("solidity", false, "output solidity code for the circuit")

	flag.Parse()

	if plonky2Circuit == nil || *plonky2Circuit == "" {
		fmt.Println("Please provide a plonky2 circuit to benchmark")
		os.Exit(1)
	}

	r1cs, pk, vk := compileCircuit(*plonky2Circuit, *profileCircuit, *serialize, *outputSolidity)
	createProof(*plonky2Circuit, r1cs, pk, vk, *serialize)
}
