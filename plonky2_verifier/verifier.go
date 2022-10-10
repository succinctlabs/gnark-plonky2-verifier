package plonky2_verifier

type Proof struct {
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
}

type CommonCircuitData struct {
	Config struct {
		NumWires                int  `json:"num_wires"`
		NumRoutedWires          int  `json:"num_routed_wires"`
		NumConstants            int  `json:"num_constants"`
		UseBaseArithmeticGate   bool `json:"use_base_arithmetic_gate"`
		SecurityBits            int  `json:"security_bits"`
		NumChallenges           int  `json:"num_challenges"`
		ZeroKnowledge           bool `json:"zero_knowledge"`
		MaxQuotientDegreeFactor int  `json:"max_quotient_degree_factor"`
		FriConfig               struct {
			RateBits          int `json:"rate_bits"`
			CapHeight         int `json:"cap_height"`
			ProofOfWorkBits   int `json:"proof_of_work_bits"`
			ReductionStrategy struct {
				ConstantArityBits []int `json:"ConstantArityBits"`
			} `json:"reduction_strategy"`
			NumQueryRounds int `json:"num_query_rounds"`
		} `json:"fri_config"`
	} `json:"config"`
	FriParams struct {
		Config struct {
			RateBits          int `json:"rate_bits"`
			CapHeight         int `json:"cap_height"`
			ProofOfWorkBits   int `json:"proof_of_work_bits"`
			ReductionStrategy struct {
				ConstantArityBits []int `json:"ConstantArityBits"`
			} `json:"reduction_strategy"`
			NumQueryRounds int `json:"num_query_rounds"`
		} `json:"config"`
		Hiding             bool          `json:"hiding"`
		DegreeBits         int           `json:"degree_bits"`
		ReductionArityBits []interface{} `json:"reduction_arity_bits"`
	} `json:"fri_params"`
	DegreeBits    int `json:"degree_bits"`
	SelectorsInfo struct {
		SelectorIndices []int `json:"selector_indices"`
		Groups          []struct {
			Start int `json:"start"`
			End   int `json:"end"`
		} `json:"groups"`
	} `json:"selectors_info"`
	QuotientDegreeFactor int           `json:"quotient_degree_factor"`
	NumGateConstraints   int           `json:"num_gate_constraints"`
	NumConstants         int           `json:"num_constants"`
	NumPublicInputs      int           `json:"num_public_inputs"`
	KIs                  []interface{} `json:"k_is"`
	NumPartialProducts   int           `json:"num_partial_products"`
	CircuitDigest        struct {
		Elements []int64 `json:"elements"`
	} `json:"circuit_digest"`
}

type VerifierOnlyCircuitData struct {
	ConstantsSigmasCap []struct {
		Elements []int64 `json:"elements"`
	} `json:"constants_sigmas_cap"`
}
