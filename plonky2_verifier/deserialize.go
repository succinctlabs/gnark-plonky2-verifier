package plonky2_verifier

import (
	"encoding/json"
	. "gnark-ed25519/field"
	"gnark-ed25519/utils"
	"io/ioutil"
	"os"
)

type ProofWithPublicInputsRaw struct {
	Proof struct {
		WiresCap []struct {
			Elements []uint64 `json:"elements"`
		} `json:"wires_cap"`
		PlonkZsPartialProductsCap []struct {
			Elements []uint64 `json:"elements"`
		} `json:"plonk_zs_partial_products_cap"`
		QuotientPolysCap []struct {
			Elements []uint64 `json:"elements"`
		} `json:"quotient_polys_cap"`
		Openings struct {
			Constants       [][]uint64 `json:"constants"`
			PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
			Wires           [][]uint64 `json:"wires"`
			PlonkZs         [][]uint64 `json:"plonk_zs"`
			PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
			PartialProducts [][]uint64 `json:"partial_products"`
			QuotientPolys   [][]uint64 `json:"quotient_polys"`
		} `json:"openings"`
		OpeningProof struct {
			CommitPhaseMerkleCaps []MerkleCapsRaw `json:"commit_phase_merkle_caps"`
			QueryRoundProofs      []struct {
				InitialTreesProof struct {
					EvalsProofs []EvalProofRaw `json:"evals_proofs"`
				} `json:"initial_trees_proof"`
				Steps []struct {
					Evals       [][]uint64     `json:"evals"`
					MerkleProof MerkleProofRaw `json:"merkle_proof"`
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

type MerkleCapsRaw struct {
	hashes [][]uint64
}

func (m *MerkleCapsRaw) UnmarshalJSON(data []byte) error {
	var merkleCaps []map[string][]uint64
	if err := json.Unmarshal(data, &merkleCaps); err != nil {
		panic(err)
	}

	m.hashes = make([][]uint64, len(merkleCaps))
	for i := 0; i < len(merkleCaps); i++ {
		m.hashes[i] = merkleCaps[i]["elements"]
	}
	return nil
}

type EvalProofRaw struct {
	leafElements []uint64
	merkleProof  MerkleProofRaw
}

func (e *EvalProofRaw) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &[]interface{}{&e.leafElements, &e.merkleProof})
}

type MerkleProofRaw struct {
	hash [][]uint64
}

func (m *MerkleProofRaw) UnmarshalJSON(data []byte) error {
	type SiblingObject struct {
		Siblings []map[string][]uint64 // "siblings"
	}

	var siblings SiblingObject
	if err := json.Unmarshal(data, &siblings); err != nil {
		panic(err)
	}

	m.hash = make([][]uint64, len(siblings.Siblings))
	for siblingIdx, sibling := range siblings.Siblings {
		m.hash[siblingIdx] = sibling["elements"]
	}

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
	DegreeBits    uint64 `json:"degree_bits"`
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
	CircuitDigest        struct {
		Elements []uint64 `json:"elements"`
	} `json:"circuit_digest"`
}

type VerifierOnlyCircuitDataRaw struct {
	ConstantsSigmasCap []struct {
		Elements []uint64 `json:"elements"`
	} `json:"constants_sigmas_cap"`
}

func DeserializeMerkleCap(merkleCapRaw []struct{ Elements []uint64 }) MerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]Hash, n)
	for i := 0; i < n; i++ {
		copy(merkleCap[i][:], utils.Uint64ArrayToFArray(merkleCapRaw[i].Elements))
	}
	return merkleCap
}

func DeserializeMerkleProof(merkleProofRaw struct{ Siblings []interface{} }) MerkleProof {
	n := len(merkleProofRaw.Siblings)
	var mp MerkleProof
	mp.Siblings = make([]Hash, n)
	for i := 0; i < n; i++ {
		element := merkleProofRaw.Siblings[i].(struct{ Elements []uint64 })
		copy(mp.Siblings[i][:], utils.Uint64ArrayToFArray(element.Elements))
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
}) OpeningSet {
	return OpeningSet{
		Constants:       utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   utils.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
	}
}

func DeserializeFriProof(openingProofRaw struct {
	CommitPhaseMerkleCaps []MerkleCapsRaw
	QueryRoundProofs      []struct {
		InitialTreesProof struct {
			EvalsProofs []EvalProofRaw
		}
		Steps []struct {
			Evals       [][]uint64
			MerkleProof MerkleProofRaw
		}
	}
	FinalPoly struct {
		Coeffs [][]uint64
	}
	PowWitness uint64
}) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = NewFieldElement(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = utils.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]MerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = utils.Uint64ArrayToHashArray(openingProofRaw.CommitPhaseMerkleCaps[i].hashes)
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]EvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = utils.Uint64ArrayToFArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].leafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = utils.Uint64ArrayToHashArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].merkleProof.hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = utils.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = utils.Uint64ArrayToHashArray(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.hash)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(path string) ProofWithPublicInputs {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := ioutil.ReadAll(jsonFile)

	var raw ProofWithPublicInputsRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var proofWithPis ProofWithPublicInputs
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap([]struct{ Elements []uint64 }(raw.Proof.WiresCap))
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap([]struct{ Elements []uint64 }(raw.Proof.PlonkZsPartialProductsCap))
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap([]struct{ Elements []uint64 }(raw.Proof.QuotientPolysCap))
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
		CommitPhaseMerkleCaps []MerkleCapsRaw
		QueryRoundProofs      []struct {
			InitialTreesProof struct {
				EvalsProofs []EvalProofRaw
			}
			Steps []struct {
				Evals       [][]uint64
				MerkleProof MerkleProofRaw
			}
		}
		FinalPoly  struct{ Coeffs [][]uint64 }
		PowWitness uint64
	}(raw.Proof.OpeningProof))
	proofWithPis.PublicInputs = utils.Uint64ArrayToFArray(raw.PublicInputs)

	return proofWithPis
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

func DeserializeCommonCircuitData(path string) CommonCircuitData {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := ioutil.ReadAll(jsonFile)

	var raw CommonCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	var commonCircuitData CommonCircuitData
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
	commonCircuitData.FriParams.Config.RateBits = raw.FriParams.Config.RateBits
	commonCircuitData.FriParams.Config.CapHeight = raw.FriParams.Config.CapHeight
	commonCircuitData.FriParams.Config.ProofOfWorkBits = raw.FriParams.Config.ProofOfWorkBits
	commonCircuitData.FriParams.Config.NumQueryRounds = raw.FriParams.Config.NumQueryRounds
	commonCircuitData.FriParams.ReductionArityBits = raw.FriParams.ReductionArityBits

	commonCircuitData.DegreeBits = raw.DegreeBits
	commonCircuitData.QuotientDegreeFactor = raw.QuotientDegreeFactor
	commonCircuitData.NumGateConstraints = raw.NumGateConstraints
	commonCircuitData.NumConstants = raw.NumConstants
	commonCircuitData.NumPublicInputs = raw.NumPublicInputs
	commonCircuitData.KIs = utils.Uint64ArrayToFArray(raw.KIs)
	commonCircuitData.NumPartialProducts = raw.NumPartialProducts
	copy(commonCircuitData.CircuitDigest[:], utils.Uint64ArrayToFArray(raw.CircuitDigest.Elements))

	return commonCircuitData
}

func DeserializeVerifierOnlyCircuitData(path string) VerifierOnlyCircuitData {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := ioutil.ReadAll(jsonFile)

	var raw VerifierOnlyCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return VerifierOnlyCircuitData{
		ConstantSigmasCap: DeserializeMerkleCap([]struct{ Elements []uint64 }(raw.ConstantsSigmasCap)),
	}
}
