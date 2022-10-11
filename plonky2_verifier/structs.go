package plonky2_verifier

import (
	. "gnark-ed25519/goldilocks"
)

type Hash = [4]GoldilocksElement
type QuadraticExtension = [2]GoldilocksElement
type MerkleCap = []Hash

type MerkleProof struct {
	Siblings []Hash
}

type EvalProof struct {
	Elements    []GoldilocksElement
	MerkleProof MerkleProof
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof
}

type FriQueryStep struct {
	Evals       []QuadraticExtension
	MerkleProof MerkleProof
}

type FriQueryRound struct {
	InitialTreesProof FriInitialTreeProof
	Steps             []FriQueryStep
}

type PolynomialCoeffs struct {
	Coeffs []GoldilocksElement
}

type FriProof struct {
	CommitPhaseMerkleCaps []MerkleCap
	QueryRoundProofs      FriQueryRound
	FinalPoly             PolynomialCoeffs
	PowWitness            GoldilocksElement
}

type OpeningSet struct {
	Constants       []QuadraticExtension
	PlonkSigmas     []QuadraticExtension
	Wires           []QuadraticExtension
	PlonkZs         []QuadraticExtension
	PlonkZsNext     []QuadraticExtension
	PartialProducts []QuadraticExtension
	QuotientPolys   []QuadraticExtension
}

type Proof struct {
	WiresCap                  MerkleCap
	PlonkZsPartialProductsCap MerkleCap
	QuotientPolysCap          MerkleCap
	Openings                  OpeningSet
	OpeningProof              FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []GoldilocksElement
}

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
			CommitPhaseMerkleCaps []interface{} `json:"commit_phase_merkle_caps"`
			QueryRoundProofs      []struct {
				InitialTreesProof struct {
					EvalsProofs [][]interface{} `json:"evals_proofs"`
				} `json:"initial_trees_proof"`
				Steps []interface{} `json:"steps"`
			} `json:"query_round_proofs"`
			FinalPoly struct {
				Coeffs [][]uint64 `json:"coeffs"`
			} `json:"final_poly"`
			PowWitness uint64 `json:"pow_witness"`
		} `json:"opening_proof"`
	} `json:"proof"`
	PublicInputs []uint64 `json:"public_inputs"`
}

type CommonCircuitData struct {
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
		Hiding             bool          `json:"hiding"`
		DegreeBits         uint64        `json:"degree_bits"`
		ReductionArityBits []interface{} `json:"reduction_arity_bits"`
	} `json:"fri_params"`
	DegreeBits    uint64 `json:"degree_bits"`
	SelectorsInfo struct {
		SelectorIndices []uint64 `json:"selector_indices"`
		Groups          []struct {
			Start uint64 `json:"start"`
			End   uint64 `json:"end"`
		} `json:"groups"`
	} `json:"selectors_info"`
	QuotientDegreeFactor uint64        `json:"quotient_degree_factor"`
	NumGateConstraints   uint64        `json:"num_gate_constraints"`
	NumConstants         uint64        `json:"num_constants"`
	NumPublicInputs      uint64        `json:"num_public_inputs"`
	KIs                  []interface{} `json:"k_is"`
	NumPartialProducts   uint64        `json:"num_partial_products"`
	CircuitDigest        struct {
		Elements []uint64 `json:"elements"`
	} `json:"circuit_digest"`
}

type VerifierOnlyCircuitData struct {
	ConstantsSigmasCap []struct {
		Elements []uint64 `json:"elements"`
	} `json:"constants_sigmas_cap"`
}
