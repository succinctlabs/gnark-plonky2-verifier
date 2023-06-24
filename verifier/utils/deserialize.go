package utils

import (
	"encoding/json"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/gl"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/utils"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/gates"
)

type ProofWithPublicInputsRaw struct {
	Proof struct {
		WiresCap                  []string `json:"wires_cap"`
		PlonkZsPartialProductsCap []string `json:"plonk_zs_partial_products_cap"`
		QuotientPolysCap          []string `json:"quotient_polys_cap"`
		Openings                  struct {
			Constants       [][]uint64 `json:"constants"`
			PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
			Wires           [][]uint64 `json:"wires"`
			PlonkZs         [][]uint64 `json:"plonk_zs"`
			PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
			PartialProducts [][]uint64 `json:"partial_products"`
			QuotientPolys   [][]uint64 `json:"quotient_polys"`
		} `json:"openings"`
		OpeningProof struct {
			CommitPhaseMerkleCaps [][]string `json:"commit_phase_merkle_caps"`
			QueryRoundProofs      []struct {
				InitialTreesProof struct {
					EvalsProofs []EvalProofRaw `json:"evals_proofs"`
				} `json:"initial_trees_proof"`
				Steps []struct {
					Evals       [][]uint64 `json:"evals"`
					MerkleProof struct {
						Siblings []string `json:"siblings"`
					} `json:"merkle_proof"`
				} `json:"steps"`
			} `json:"query_round_proofs"`
			FinalPoly struct {
				Coeffs [][]uint64 `json:"coeffs"`
			} `json:"final_poly"`
			PowWitness uint64 `json:"pow_witness"`
		} `json:"opening_proof"`
	} `json:"proof"`
	PublicInputs []uint64 `json:"public_inputs"`
}

type EvalProofRaw struct {
	LeafElements []uint64
	MerkleProof  MerkleProofRaw
}

func (e *EvalProofRaw) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &[]interface{}{&e.LeafElements, &e.MerkleProof})
}

type MerkleProofRaw struct {
	Hash []string
}

func (m *MerkleProofRaw) UnmarshalJSON(data []byte) error {
	type SiblingObject struct {
		Siblings []string // "siblings"
	}

	var siblings SiblingObject
	if err := json.Unmarshal(data, &siblings); err != nil {
		panic(err)
	}

	m.Hash = make([]string, len(siblings.Siblings))
	copy(m.Hash[:], siblings.Siblings)

	return nil
}

type CommonCircuitDataRaw struct {
	Config struct {
		NumWires                uint64 `json:"num_wires"`
		NumRoutedWires          uint64 `json:"num_routed_wires"`
		NumConstants            uint64 `json:"num_constants"`
		UseBaseArithmeticGate   bool   `json:"use_base_arithmetic_gate"`
		SecurityBits            uint64 `json:"security_bits"`
		NumChallenges           uint64 `json:"num_challenges"`
		ZeroKnowledge           bool   `json:"zero_knowledge"`
		MaxQuotientDegreeFactor uint64 `json:"max_quotient_degree_factor"`
		FriConfig               struct {
			RateBits          uint64 `json:"rate_bits"`
			CapHeight         uint64 `json:"cap_height"`
			ProofOfWorkBits   uint64 `json:"proof_of_work_bits"`
			ReductionStrategy struct {
				ConstantArityBits []uint64 `json:"ConstantArityBits"`
			} `json:"reduction_strategy"`
			NumQueryRounds uint64 `json:"num_query_rounds"`
		} `json:"fri_config"`
	} `json:"config"`
	FriParams struct {
		Config struct {
			RateBits          uint64 `json:"rate_bits"`
			CapHeight         uint64 `json:"cap_height"`
			ProofOfWorkBits   uint64 `json:"proof_of_work_bits"`
			ReductionStrategy struct {
				ConstantArityBits []uint64 `json:"ConstantArityBits"`
			} `json:"reduction_strategy"`
			NumQueryRounds uint64 `json:"num_query_rounds"`
		} `json:"config"`
		Hiding             bool     `json:"hiding"`
		DegreeBits         uint64   `json:"degree_bits"`
		ReductionArityBits []uint64 `json:"reduction_arity_bits"`
	} `json:"fri_params"`
	Gates         []string `json:"gates"`
	SelectorsInfo struct {
		SelectorIndices []uint64 `json:"selector_indices"`
		Groups          []struct {
			Start uint64 `json:"start"`
			End   uint64 `json:"end"`
		} `json:"groups"`
	} `json:"selectors_info"`
	QuotientDegreeFactor uint64   `json:"quotient_degree_factor"`
	NumGateConstraints   uint64   `json:"num_gate_constraints"`
	NumConstants         uint64   `json:"num_constants"`
	NumPublicInputs      uint64   `json:"num_public_inputs"`
	KIs                  []uint64 `json:"k_is"`
	NumPartialProducts   uint64   `json:"num_partial_products"`
}

type ProofChallengesRaw struct {
	PlonkBetas    []uint64 `json:"plonk_betas"`
	PlonkGammas   []uint64 `json:"plonk_gammas"`
	PlonkAlphas   []uint64 `json:"plonk_alphas"`
	PlonkZeta     []uint64 `json:"plonk_zeta"`
	FriChallenges struct {
		FriAlpha        []uint64   `json:"fri_alpha"`
		FriBetas        [][]uint64 `json:"fri_betas"`
		FriPowResponse  uint64     `json:"fri_pow_response"`
		FriQueryIndices []uint64   `json:"fri_query_indices"`
	} `json:"fri_challenges"`
}

type VerifierOnlyCircuitDataRaw struct {
	ConstantsSigmasCap []string `json:"constants_sigmas_cap"`
	CircuitDigest      string   `json:"circuit_digest"`
}

func DeserializeMerkleCap(merkleCapRaw []string) common.MerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]poseidon.PoseidonBN128HashOut, n)
	for i := 0; i < n; i++ {
		capBigInt, _ := new(big.Int).SetString(merkleCapRaw[i], 10)
		merkleCap[i] = frontend.Variable(capBigInt)
	}
	return merkleCap
}

func DeserializeMerkleProof(merkleProofRaw struct{ Siblings []interface{} }) common.MerkleProof {
	n := len(merkleProofRaw.Siblings)
	var mp common.MerkleProof
	mp.Siblings = make([]poseidon.PoseidonBN128HashOut, n)
	for i := 0; i < n; i++ {
		element := merkleProofRaw.Siblings[i].(struct{ Elements []uint64 })
		mp.Siblings[i] = utils.Uint64ArrayToFArray(element.Elements)
	}
	return mp
}

func DeserializeOpeningSet(openingSetRaw struct {
	Constants       [][]uint64
	PlonkSigmas     [][]uint64
	Wires           [][]uint64
	PlonkZs         [][]uint64
	PlonkZsNext     [][]uint64
	PartialProducts [][]uint64
	QuotientPolys   [][]uint64
}) common.OpeningSet {
	return common.OpeningSet{
		Constants:       utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
	}
}

func StringArrayToHashBN128Array(rawHashes []string) []poseidon.PoseidonBN128HashOut {
	hashes := []poseidon.PoseidonBN128HashOut{}

	for i := 0; i < len(rawHashes); i++ {
		hashBigInt, _ := new(big.Int).SetString(rawHashes[i], 10)
		hashVar := frontend.Variable(hashBigInt)
		hashes = append(hashes, poseidon.PoseidonBN128HashOut(hashVar))
	}

	return hashes
}

func DeserializeFriProof(openingProofRaw struct {
	CommitPhaseMerkleCaps [][]string
	QueryRoundProofs      []struct {
		InitialTreesProof struct {
			EvalsProofs []EvalProofRaw
		}
		Steps []struct {
			Evals       [][]uint64
			MerkleProof struct {
				Siblings []string
			}
		}
	}
	FinalPoly struct {
		Coeffs [][]uint64
	}
	PowWitness uint64
}) common.FriProof {
	var openingProof common.FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = utils.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]common.MerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = StringArrayToHashBN128Array(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]common.FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]common.EvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = utils.Uint64ArrayToFArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = StringArrayToHashBN128Array(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]common.FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = utils.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = StringArrayToHashBN128Array(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(path string) common.ProofWithPublicInputs {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw ProofWithPublicInputsRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var proofWithPis common.ProofWithPublicInputs
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap(raw.Proof.WiresCap)
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap(raw.Proof.PlonkZsPartialProductsCap)
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap(raw.Proof.QuotientPolysCap)
	proofWithPis.Proof.Openings = DeserializeOpeningSet(struct {
		Constants       [][]uint64
		PlonkSigmas     [][]uint64
		Wires           [][]uint64
		PlonkZs         [][]uint64
		PlonkZsNext     [][]uint64
		PartialProducts [][]uint64
		QuotientPolys   [][]uint64
	}(raw.Proof.Openings))
	proofWithPis.Proof.OpeningProof = DeserializeFriProof(struct {
		CommitPhaseMerkleCaps [][]string
		QueryRoundProofs      []struct {
			InitialTreesProof struct {
				EvalsProofs []EvalProofRaw
			}
			Steps []struct {
				Evals       [][]uint64
				MerkleProof struct {
					Siblings []string
				}
			}
		}
		FinalPoly  struct{ Coeffs [][]uint64 }
		PowWitness uint64
	}(raw.Proof.OpeningProof))
	proofWithPis.PublicInputs = utils.Uint64ArrayToFArray(raw.PublicInputs)

	return proofWithPis
}

func DeserializeProofChallenges(path string) common.ProofChallenges {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw ProofChallengesRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var proofChallenges common.ProofChallenges
	proofChallenges.PlonkBetas = utils.Uint64ArrayToFArray(raw.PlonkBetas)
	proofChallenges.PlonkGammas = utils.Uint64ArrayToFArray(raw.PlonkGammas)
	proofChallenges.PlonkAlphas = utils.Uint64ArrayToFArray(raw.PlonkAlphas)
	proofChallenges.PlonkZeta = utils.Uint64ArrayToQuadraticExtension(raw.PlonkZeta)
	proofChallenges.FriChallenges.FriAlpha = utils.Uint64ArrayToQuadraticExtension(raw.FriChallenges.FriAlpha)
	proofChallenges.FriChallenges.FriBetas = utils.Uint64ArrayToQuadraticExtensionArray(raw.FriChallenges.FriBetas)
	proofChallenges.FriChallenges.FriPowResponse = gl.NewVariable(raw.FriChallenges.FriPowResponse)
	proofChallenges.FriChallenges.FriQueryIndices = utils.Uint64ArrayToFArray(raw.FriChallenges.FriQueryIndices)

	return proofChallenges
}

func ReductionArityBits(
	arityBits uint64,
	finalPolyBits uint64,
	degreeBits uint64,
	rateBits uint64,
	capHeight uint64,
) []uint64 {
	returnArr := make([]uint64, 0)

	for degreeBits > finalPolyBits && degreeBits+rateBits-arityBits >= capHeight {
		returnArr = append(returnArr, arityBits)
		if degreeBits < arityBits {
			panic("degreeBits < arityBits")
		}
		degreeBits -= arityBits
	}

	return returnArr
}

func DeserializeCommonCircuitData(path string) common.CommonCircuitData {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw CommonCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var commonCircuitData common.CommonCircuitData
	commonCircuitData.Config.NumWires = raw.Config.NumWires
	commonCircuitData.Config.NumRoutedWires = raw.Config.NumRoutedWires
	commonCircuitData.Config.NumConstants = raw.Config.NumConstants
	commonCircuitData.Config.UseBaseArithmeticGate = raw.Config.UseBaseArithmeticGate
	commonCircuitData.Config.SecurityBits = raw.Config.SecurityBits
	commonCircuitData.Config.NumChallenges = raw.Config.NumChallenges
	commonCircuitData.Config.ZeroKnowledge = raw.Config.ZeroKnowledge
	commonCircuitData.Config.MaxQuotientDegreeFactor = raw.Config.MaxQuotientDegreeFactor

	commonCircuitData.Config.FriConfig.RateBits = raw.Config.FriConfig.RateBits
	commonCircuitData.Config.FriConfig.CapHeight = raw.Config.FriConfig.CapHeight
	commonCircuitData.Config.FriConfig.ProofOfWorkBits = raw.Config.FriConfig.ProofOfWorkBits
	commonCircuitData.Config.FriConfig.NumQueryRounds = raw.Config.FriConfig.NumQueryRounds

	commonCircuitData.FriParams.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.FriParams.Config.RateBits = raw.FriParams.Config.RateBits
	commonCircuitData.FriParams.Config.CapHeight = raw.FriParams.Config.CapHeight
	commonCircuitData.FriParams.Config.ProofOfWorkBits = raw.FriParams.Config.ProofOfWorkBits
	commonCircuitData.FriParams.Config.NumQueryRounds = raw.FriParams.Config.NumQueryRounds
	commonCircuitData.FriParams.ReductionArityBits = raw.FriParams.ReductionArityBits

	commonCircuitData.Gates = []gates.Gate{}
	for _, gate := range raw.Gates {
		commonCircuitData.Gates = append(commonCircuitData.Gates, gates.GateInstanceFromId(gate))
	}

	selectorGroupStart := []uint64{}
	selectorGroupEnd := []uint64{}
	for _, group := range raw.SelectorsInfo.Groups {
		selectorGroupStart = append(selectorGroupStart, group.Start)
		selectorGroupEnd = append(selectorGroupEnd, group.End)
	}

	commonCircuitData.SelectorsInfo = *gates.NewSelectorsInfo(
		raw.SelectorsInfo.SelectorIndices,
		selectorGroupStart,
		selectorGroupEnd,
	)

	commonCircuitData.QuotientDegreeFactor = raw.QuotientDegreeFactor
	commonCircuitData.NumGateConstraints = raw.NumGateConstraints
	commonCircuitData.NumConstants = raw.NumConstants
	commonCircuitData.NumPublicInputs = raw.NumPublicInputs
	commonCircuitData.KIs = utils.Uint64ArrayToFArray(raw.KIs)
	commonCircuitData.NumPartialProducts = raw.NumPartialProducts

	return commonCircuitData
}

func DeserializeVerifierOnlyCircuitData(path string) common.VerifierOnlyCircuitData {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw VerifierOnlyCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var verifierOnlyCircuitData common.VerifierOnlyCircuitData
	verifierOnlyCircuitData.ConstantSigmasCap = DeserializeMerkleCap(raw.ConstantsSigmasCap)
	circuitDigestBigInt, _ := new(big.Int).SetString(raw.CircuitDigest, 10)
	circuitDigestVar := frontend.Variable(circuitDigestBigInt)
	verifierOnlyCircuitData.CircuitDigest = poseidon.PoseidonBN128HashOut(circuitDigestVar)
	return verifierOnlyCircuitData
}
