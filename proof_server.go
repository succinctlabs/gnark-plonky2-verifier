package main

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type Plonky2VerifierCircuit struct {
	Proof        common.Proof
	PublicInputs []field.F `gnark:",public"`

	verifierChip       *verifier.VerifierChip `gnark:"-"`
	plonky2CircuitName string                 `gnark:"-"`
}

func (circuit *Plonky2VerifierCircuit) Define(api frontend.API) error {
	circuitDirname := "./verifier/data/" + circuit.plonky2CircuitName + "/"
	commonCircuitData := utils.DeserializeCommonCircuitData(circuitDirname + "common_circuit_data.json")
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuitDirname + "verifier_only_circuit_data.json")

	circuit.verifierChip = verifier.NewVerifierChip(api, commonCircuitData)

	circuit.verifierChip.Verify(circuit.Proof, circuit.PublicInputs, verifierOnlyCircuitData, commonCircuitData)

	return nil
}

func compileCircuit(plonky2Circuit string, profileCircuit bool, serialize bool, outputSolidity bool) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	circuit := Plonky2VerifierCircuit{
		plonky2CircuitName: plonky2Circuit,
	}
	proofWithPis := utils.DeserializeProofWithPublicInputsFromFile("./verifier/data/" + plonky2Circuit + "/proof_with_public_inputs.json")
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

func createProof(serializedProofWithPI string, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, serialize bool) groth16.Proof {
	proofWithPis := utils.DeserializeProofWithPublicInputs(serializedProofWithPI)

	// Witness
	assignment := &Plonky2VerifierCircuit{
		Proof:        proofWithPis.Proof,
		PublicInputs: proofWithPis.PublicInputs,
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	if serialize {
		fWitness, _ := os.Create("witness")
		witness.WriteTo(fWitness)
		fWitness.Close()
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if serialize {
		fProof, _ := os.Create("proof.proof")
		proof.WriteTo(fProof)
		fProof.Close()
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

func generateProof(conn net.Conn, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	log.Printf("Client connected [%s]", conn.RemoteAddr().Network())
	defer conn.Close()

	const MAX_PROOF_SIZE = 500000
	buf := make([]byte, MAX_PROOF_SIZE)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading from socket: %s", err)
		return
	}

	if n == MAX_PROOF_SIZE {
		log.Printf("Proof too large")
		return
	}

	createProof(string(buf), r1cs, pk, vk, false)
}

func main() {
	const SockAddr = "/tmp/echo.sock"

	r1cs, pk, vk := compileCircuit("step", false, false, false)
	println("Done compiling circuit")

	if err := os.RemoveAll(SockAddr); err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("unix", SockAddr)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()

	for {
		// Accept new connections, dispatching them to echoServer
		// in a goroutine.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go generateProof(conn, r1cs, pk, vk)
	}
}
