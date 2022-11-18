package main

import (
	"fmt"
	. "gnark-ed25519/field"
	. "gnark-ed25519/plonky2_verifier"
	"gnark-ed25519/poseidon"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type BenchmarkLargeDummyFriCircuit struct {
	zeta              QuadraticExtension
	openings          FriOpenings
	friChallenges     FriChallenges
	initialMerkleCaps []MerkleCap
	friProof          FriProof
}

func (circuit *BenchmarkLargeDummyFriCircuit) Define(api frontend.API) error {
	commonCircuitData := DeserializeCommonCircuitData("./plonky2_verifier/data/dummy_2^14_gates/common_circuit_data.json")

	field := NewFieldAPI(api)
	qeAPI := NewQuadraticExtensionAPI(field, commonCircuitData.DegreeBits)
	poseidonChip := poseidon.NewPoseidonChip(api, field)
	friChip := NewFriChip(api, field, qeAPI, poseidonChip, &commonCircuitData.FriParams)

	friChip.VerifyFriProof(
		commonCircuitData.GetFriInstance(qeAPI, circuit.zeta, commonCircuitData.DegreeBits),
		circuit.openings,
		&circuit.friChallenges,
		circuit.initialMerkleCaps,
		&circuit.friProof,
	)

	return nil
}

func compileCircuit() frontend.CompiledConstraintSystem {
	fmt.Println("compiling circuit", time.Now())
	circuit := BenchmarkLargeDummyFriCircuit{}

	/*
		commonCircuitData := DeserializeCommonCircuitData("./plonky2_verifier/data/dummy_2^14_gates/common_circuit_data.json")

		circuit.zeta[0] = emulated.NewElement[EmulatedField](nil)
		circuit.zeta[1] = emulated.NewElement[EmulatedField](nil)

		fmt.Println("circuit zeta allocated")

		// Batch 0 has the following openings
		// Constants (config.num_constants + 1)
		// Sigmas (config.num_routed_wires)
		// Wires (config.num_wires)
		// Plonk_Z (config.num_challenges)
		// Partial Products (config.num_challenges * config.num_partial_products)
		// Quotient Polynomails (config.num_challenges * config.quotient_degree_factor)

		// Batch 1 has the following openings
		// Plonk_Z_next (config.num_challenges)

		circuit.openings.Batches = make([]FriOpeningBatch, 2)

		batch1Size := commonCircuitData.NumConstants + 1 +
			commonCircuitData.Config.NumRoutedWires +
			commonCircuitData.Config.NumWires +
			commonCircuitData.Config.NumChallenges +
			(commonCircuitData.Config.NumChallenges * commonCircuitData.NumPartialProducts) +
			(commonCircuitData.Config.NumChallenges * commonCircuitData.QuotientDegreeFactor)

		circuit.openings.Batches[0].Values = make([]QuadraticExtension, 0)
		for i := uint64(0); i < batch1Size; i++ {
			circuit.openings.Batches[0].Values = append(circuit.openings.Batches[0].Values, NewEmptyQuadraticExtension())
		}

		batch2Size := commonCircuitData.Config.NumChallenges
		circuit.openings.Batches[1].Values = make([]QuadraticExtension, 0)
		for i := uint64(0); i < batch2Size; i++ {
			circuit.openings.Batches[1].Values = append(circuit.openings.Batches[1].Values, NewEmptyQuadraticExtension())
		}

		fmt.Println("circuit openings allocated")

		circuit.friChallenges.FriAlpha = NewEmptyQuadraticExtension()
		circuit.friChallenges.FriPowResponse = emulated.NewElement[EmulatedField](nil)
		circuit.friChallenges.FriBetas = make([]QuadraticExtension, 0)
		for i := 0; i < len(commonCircuitData.FriParams.ReductionArityBits); i++ {
			circuit.friChallenges.FriBetas = append(circuit.friChallenges.FriBetas, NewEmptyQuadraticExtension())
		}
		circuit.friChallenges.FriQueryIndicies = make([]F, 0)
		for i := uint64(0); i < commonCircuitData.FriParams.Config.NumQueryRounds; i++ {
			circuit.friChallenges.FriQueryIndicies = append(circuit.friChallenges.FriQueryIndicies, NewEmptyFieldElement())
		}

		fmt.Println("circuit challenges allocated")

		// initial merkle caps is the merkle cap for
		// the constant/sigmas, wires, partial products,
		// and quotient composite polynomial
		// The merkle cap size is 2**cap_height hashes
		numMerkleCaps := 4
		merkleCapSize := 1 << commonCircuitData.Config.FriConfig.CapHeight
		circuit.initialMerkleCaps = make([]MerkleCap, 0)
		for i := 0; i < numMerkleCaps; i++ {
			merkleCap := make([]Hash, 0)
			for j := 0; j < merkleCapSize; j++ {
				merkleCap = append(merkleCap, NewEmptyHash())
			}
			circuit.initialMerkleCaps = append(circuit.initialMerkleCaps, merkleCap)
		}

		fmt.Println("circuit initialMerkleCaps allocated")

		// CommitPhaseMerkleCap is number of reduction_arity_bits
		// finalPoly has 2^(degreeBits - sum(arity_bits)) coefficients
		numCommitPhaseMerkleCaps := len(commonCircuitData.FriParams.ReductionArityBits)
		for i := 0; i < numCommitPhaseMerkleCaps; i++ {
			circuit.friProof.CommitPhaseMerkleCaps = make([]MerkleCap, 0)
			merkleCap := make([]Hash, 0)
			for j := 0; j < merkleCapSize; j++ {
				merkleCap = append(merkleCap, NewEmptyHash())
			}
			circuit.friProof.CommitPhaseMerkleCaps = append(circuit.friProof.CommitPhaseMerkleCaps, merkleCap)
		}

		fmt.Println("circuit friproof CommitPhaseMerkleCaps allocated")

		friOracleInfo := commonCircuitData.FriOracles()
		circuit.friProof.QueryRoundProofs = make([]FriQueryRound, 0)
		for i := 0; i < int(commonCircuitData.FriParams.Config.NumQueryRounds); i++ {

			evalsProof := make([]EvalProof, 0)
			// Allocation for the initial trees proof
			for j := 0; j < len(friOracleInfo); j++ {
				leafSize := friOracleInfo[0].NumPolys
				merkleProofLen := commonCircuitData.DegreeBits + commonCircuitData.Config.FriConfig.RateBits - commonCircuitData.Config.FriConfig.CapHeight

				evalElements := make([]F, 0)
				for k := uint64(0); k < leafSize; k++ {
					evalElements = append(evalElements, NewEmptyFieldElement())
				}

				merkleProofSiblings := make([]Hash, 0)
				for k := uint64(0); k < merkleProofLen; k++ {
					merkleProofSiblings = append(merkleProofSiblings, NewEmptyHash())
				}

				evalsProof = append(
					evalsProof,
					EvalProof{
						Elements:    evalElements,
						MerkleProof: MerkleProof{merkleProofSiblings},
					},
				)
			}

			// Allocation for the steps
			steps := make([]FriQueryStep, 0)
			codewordLenBits := commonCircuitData.DegreeBits + commonCircuitData.Config.FriConfig.RateBits
			for j := 0; j < len(commonCircuitData.FriParams.ReductionArityBits); j++ {
				arityBits := commonCircuitData.FriParams.ReductionArityBits[j]
				leafSize := 1 << int(arityBits)
				codewordLenBits -= arityBits
				merkleProofLen := codewordLenBits - commonCircuitData.Config.FriConfig.CapHeight

				evalQEs := make([]QuadraticExtension, 0)
				for k := 0; k < leafSize; k++ {
					evalQEs = append(evalQEs, NewEmptyQuadraticExtension())
				}

				merkleProofSiblings := make([]Hash, 0)
				for k := uint64(0); k < merkleProofLen; k++ {
					merkleProofSiblings = append(merkleProofSiblings, NewEmptyHash())
				}

				steps = append(
					steps,
					FriQueryStep{
						Evals:       evalQEs,
						MerkleProof: MerkleProof{merkleProofSiblings},
					},
				)
			}

			circuit.friProof.QueryRoundProofs = append(
				circuit.friProof.QueryRoundProofs,
				FriQueryRound{
					InitialTreesProof: FriInitialTreeProof{evalsProof},
					Steps:             steps,
				},
			)

			fmt.Println("circuit friproof QueryRoundProofs allocated for round", i)
		}

		// Final poly allocation
		finalPolyLenBit := commonCircuitData.DegreeBits
		for _, arityBit := range commonCircuitData.FriParams.ReductionArityBits {
			finalPolyLenBit -= arityBit
		}

		circuit.friProof.FinalPoly.Coeffs = make([]QuadraticExtension, 0)
		for i := 0; i < (1 << finalPolyLenBit); i++ {
			circuit.friProof.FinalPoly.Coeffs = append(circuit.friProof.FinalPoly.Coeffs, NewEmptyQuadraticExtension())
		}

		fmt.Println("circuit friproof FinalPoly allocated")

		// PowWitness allocation
		circuit.friProof.PowWitness = NewEmptyFieldElement()
		fmt.Println("Partial witness allocation done")
	*/

	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./plonky2_verifier/data/dummy_2^14_gates/verifier_only_circuit_data.json")

	zeta := QuadraticExtension{
		NewFieldElementFromString("17377750363769967882"),
		NewFieldElementFromString("11921191651424768462"),
	}
	friChallenges := FriChallenges{
		FriAlpha: QuadraticExtension{
			NewFieldElementFromString("16721004555774385479"),
			NewFieldElementFromString("10688151135543754663"),
		},
		FriBetas: []QuadraticExtension{
			{
				NewFieldElementFromString("3312441922957827805"),
				NewFieldElementFromString("15128092514958289671"),
			},
			{
				NewFieldElementFromString("13630530769060141802"),
				NewFieldElementFromString("14559883974933163008"),
			},
			{
				NewFieldElementFromString("16146508250083930687"),
				NewFieldElementFromString("5176346568444408396"),
			},
		},
		FriPowResponse: NewFieldElement(4389),
		FriQueryIndicies: []F{
			NewFieldElementFromString("16334967868590615051"),
			NewFieldElementFromString("2911473540496037915"),
			NewFieldElementFromString("14887216056886344225"),
			NewFieldElementFromString("7808811227805914295"),
			NewFieldElementFromString("2018594961417375749"),
			NewFieldElementFromString("3733368398777208435"),
			NewFieldElementFromString("2623035669037055104"),
			NewFieldElementFromString("299243030573481514"),
			NewFieldElementFromString("7189789717962704433"),
			NewFieldElementFromString("14566344026886816268"),
			NewFieldElementFromString("12555390069003437453"),
			NewFieldElementFromString("17225508403199418233"),
			NewFieldElementFromString("5088797913879903292"),
			NewFieldElementFromString("9715691392773433023"),
			NewFieldElementFromString("7565836764713256165"),
			NewFieldElementFromString("1500143546029322929"),
			NewFieldElementFromString("1245802417104422080"),
			NewFieldElementFromString("6831959786661245110"),
			NewFieldElementFromString("17271054758535453780"),
			NewFieldElementFromString("6225460404576395409"),
			NewFieldElementFromString("15932661092896277351"),
			NewFieldElementFromString("12452534049198240575"),
			NewFieldElementFromString("4225199666055520177"),
			NewFieldElementFromString("13235091290587791090"),
			NewFieldElementFromString("2562357622728700774"),
			NewFieldElementFromString("17676678042980201498"),
			NewFieldElementFromString("5837067135702409874"),
			NewFieldElementFromString("11238419549114325157"),
		},
	}

	initialMerkleCaps := []MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	circuit.zeta = zeta
	circuit.openings = proofWithPis.Proof.Openings.ToFriOpenings()
	circuit.friChallenges = friChallenges
	circuit.initialMerkleCaps = initialMerkleCaps
	circuit.friProof = proofWithPis.Proof.OpeningProof

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	return r1cs
}

func createProof(r1cs frontend.CompiledConstraintSystem) groth16.Proof {
	proofWithPis := DeserializeProofWithPublicInputs("./plonky2_verifier/data/dummy_2^14_gates/proof_with_public_inputs.json")
	verifierOnlyCircuitData := DeserializeVerifierOnlyCircuitData("./plonky2_verifier/data/dummy_2^14_gates/verifier_only_circuit_data.json")

	zeta := QuadraticExtension{
		NewFieldElementFromString("17377750363769967882"),
		NewFieldElementFromString("11921191651424768462"),
	}
	friChallenges := FriChallenges{
		FriAlpha: QuadraticExtension{
			NewFieldElementFromString("16721004555774385479"),
			NewFieldElementFromString("10688151135543754663"),
		},
		FriBetas: []QuadraticExtension{
			{
				NewFieldElementFromString("3312441922957827805"),
				NewFieldElementFromString("15128092514958289671"),
			},
			{
				NewFieldElementFromString("13630530769060141802"),
				NewFieldElementFromString("14559883974933163008"),
			},
			{
				NewFieldElementFromString("16146508250083930687"),
				NewFieldElementFromString("5176346568444408396"),
			},
		},
		FriPowResponse: NewFieldElement(4389),
		FriQueryIndicies: []F{
			NewFieldElementFromString("16334967868590615051"),
			NewFieldElementFromString("2911473540496037915"),
			NewFieldElementFromString("14887216056886344225"),
			NewFieldElementFromString("7808811227805914295"),
			NewFieldElementFromString("2018594961417375749"),
			NewFieldElementFromString("3733368398777208435"),
			NewFieldElementFromString("2623035669037055104"),
			NewFieldElementFromString("299243030573481514"),
			NewFieldElementFromString("7189789717962704433"),
			NewFieldElementFromString("14566344026886816268"),
			NewFieldElementFromString("12555390069003437453"),
			NewFieldElementFromString("17225508403199418233"),
			NewFieldElementFromString("5088797913879903292"),
			NewFieldElementFromString("9715691392773433023"),
			NewFieldElementFromString("7565836764713256165"),
			NewFieldElementFromString("1500143546029322929"),
			NewFieldElementFromString("1245802417104422080"),
			NewFieldElementFromString("6831959786661245110"),
			NewFieldElementFromString("17271054758535453780"),
			NewFieldElementFromString("6225460404576395409"),
			NewFieldElementFromString("15932661092896277351"),
			NewFieldElementFromString("12452534049198240575"),
			NewFieldElementFromString("4225199666055520177"),
			NewFieldElementFromString("13235091290587791090"),
			NewFieldElementFromString("2562357622728700774"),
			NewFieldElementFromString("17676678042980201498"),
			NewFieldElementFromString("5837067135702409874"),
			NewFieldElementFromString("11238419549114325157"),
		},
	}

	initialMerkleCaps := []MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	// Witness
	assignment := &BenchmarkLargeDummyFriCircuit{
		zeta:              zeta,
		openings:          proofWithPis.Proof.Openings.ToFriOpenings(),
		friChallenges:     friChallenges,
		initialMerkleCaps: initialMerkleCaps,
		friProof:          proofWithPis.Proof.OpeningProof,
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
