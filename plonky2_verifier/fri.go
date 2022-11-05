package plonky2_verifier

import (
	"fmt"
	"gnark-ed25519/field"
	. "gnark-ed25519/field"
	"math"

	"github.com/consensys/gnark/frontend"
)

type FriOpeningBatch struct {
	values []QuadraticExtension
}

type FriOpenings struct {
	Batches []FriOpeningBatch
}

func (c *OpeningSet) ToFriOpenings() FriOpenings {
	values := c.Constants
	values = append(values, c.PlonkSigmas...)
	values = append(values, c.Wires...)
	values = append(values, c.PlonkZs...)
	values = append(values, c.PartialProducts...)
	values = append(values, c.QuotientPolys...)
	zetaBatch := FriOpeningBatch{values: values}
	zetaNextBatch := FriOpeningBatch{values: c.PlonkZsNext}
	return FriOpenings{Batches: []FriOpeningBatch{zetaBatch, zetaNextBatch}}
}

type FriChip struct {
	api   frontend.API
	field frontend.API
	qe    *QuadraticExtensionAPI

	friParams               *FriParams
	verifierOnlyCircuitData *VerifierOnlyCircuitData
}

func NewFriChip(api frontend.API, field frontend.API, qe *QuadraticExtensionAPI, friParams *FriParams) *FriChip {
	return &FriChip{
		api:       api,
		field:     field,
		qe:        qe,
		friParams: friParams,
	}
}

func (f *FriChip) assertLeadingZeros(powWitness F, friConfig FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least `leading_zeros` leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long
	maxPowWitness := uint64(math.Pow(2, float64(64-friConfig.ProofOfWorkBits))) - 1
	f.field.Println(powWitness)
	fmt.Println(maxPowWitness)
	fmt.Println(friConfig.ProofOfWorkBits)
	f.field.AssertIsLessOrEqual(powWitness, field.NewFieldElement(maxPowWitness))
}

func (f *FriChip) fromOpeningsAndAlpha(openings *FriOpenings, alpha QuadraticExtension) []QuadraticExtension {
	// One reduced opening for all openings evaluated at point Zeta.
	// Another one for all openings evaluated at point Zeta * Omega (which is only PlonkZsNext polynomial)

	reducedOpenings := make([]QuadraticExtension, 0, 2)
	for _, batch := range openings.Batches {
		reducedOpenings = append(reducedOpenings, reduceWithPowers(f.qe, batch.values, alpha))
	}

	return reducedOpenings
}

func (f *FriChip) verifyMerkleProofToCap(leafData []F, leafIndex F, merkleCap MerkleCap, proof *MerkleProof) {
}

func (f *FriChip) verifyInitialProof(xIndex F, proof *FriInitialTreeProof, initialMerkleCaps []MerkleCap) {
	if len(proof.EvalsProofs) != len(initialMerkleCaps) {
		panic("length of eval proofs in fri proof should equal length of initial merkle caps")
	}

	for i := 0; i < len(initialMerkleCaps); i++ {
		evals := proof.EvalsProofs[i].Elements
		merkleProof := proof.EvalsProofs[i].MerkleProof
		cap := initialMerkleCaps[i]
		f.verifyMerkleProofToCap(evals, xIndex, cap, &merkleProof)
	}
}

func (f *FriChip) verifyQueryRound(
	challenges *FriChallenges,
	precomputedReducedEval []QuadraticExtension,
	initialMerkleCaps []MerkleCap,
	proof *FriProof,
	xIndex F,
	n uint64,
	roundProof *FriQueryRound,
) {
	f.verifyInitialProof(xIndex, &roundProof.InitialTreesProof, initialMerkleCaps)
}

func (f *FriChip) VerifyFriProof(
	openings *FriOpenings,
	friChallenges *FriChallenges,
	initialMerkleCaps []MerkleCap,
	friProof *FriProof,
) {
	// TODO:  Check fri config
	/* if let Some(max_arity_bits) = params.max_arity_bits() {
		self.check_recursion_config::<C>(max_arity_bits);
	}

	debug_assert_eq!(
		params.final_poly_len(),
		proof.final_poly.len(),
		"Final polynomial has wrong degree."
	); */

	// Check POW
	f.assertLeadingZeros(friProof.PowWitness, f.friParams.Config)

	precomputedReducedEvals := f.fromOpeningsAndAlpha(openings, friChallenges.FriAlpha)

	// Size of the LDE domain.
	n := uint64(math.Pow(2, float64(f.friParams.DegreeBits+f.friParams.Config.RateBits)))

	if len(friChallenges.FriQueryIndicies) != len(precomputedReducedEvals) {
		panic("Number of queryRoundProofs should equal number of precomputedReducedEvals")
	}

	for idx, xIndex := range friChallenges.FriQueryIndicies {
		roundProof := friProof.QueryRoundProofs[idx]

		f.verifyQueryRound(
			friChallenges,
			precomputedReducedEvals,
			initialMerkleCaps,
			friProof,
			xIndex,
			n,
			&roundProof,
		)
	}
}
