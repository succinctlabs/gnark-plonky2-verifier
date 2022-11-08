package plonky2_verifier

import (
	"fmt"
	"gnark-ed25519/field"
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"
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

	poseidonChip *poseidon.PoseidonChip

	friParams               *FriParams
	verifierOnlyCircuitData *VerifierOnlyCircuitData
}

func NewFriChip(api frontend.API, field frontend.API, qe *QuadraticExtensionAPI, poseidonChip *poseidon.PoseidonChip, friParams *FriParams) *FriChip {
	return &FriChip{
		api:          api,
		field:        field,
		qe:           qe,
		poseidonChip: poseidonChip,
		friParams:    friParams,
	}
}

func (f *FriChip) assertLeadingZeros(powWitness F, friConfig FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least `leading_zeros` leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long
	maxPowWitness := uint64(math.Pow(2, float64(64-friConfig.ProofOfWorkBits))) - 1
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

func (f *FriChip) hashOrNoop(data []F) Hash {
	var elements Hash
	if len(data) <= 4 {
		// Pad the data to have a size of 4
		for i, inputElement := range data {
			elements[i] = inputElement
		}
		for i := len(data); i < 4; i++ {
			elements[i] = f.qe.ZERO_F
		}

		return elements
	} else {
		hashOutput := f.poseidonChip.HashNToMNoPad(data, 4)

		if len(hashOutput) != len(elements) {
			panic("The length of hashOutput and elements is different")
		}

		for i, hashField := range hashOutput {
			elements[i] = hashField
		}

		return elements
	}
}

func (f *FriChip) verifyMerkleProofToCapWithCapIndex(leafData []F, leafIndexBits []frontend.Variable, capIndex F, merkleCap MerkleCap, proof *MerkleProof) {
	currentDigest := f.hashOrNoop(leafData)

	if len(leafIndexBits) != len(proof.Siblings) {
		panic("len(leafIndexBits) != len(proof.Siblings)")
	}

	fourZeros := [4]F{f.qe.ZERO_F, f.qe.ZERO_F, f.qe.ZERO_F, f.qe.ZERO_F}
	for i, bit := range leafIndexBits {
		sibling := proof.Siblings[i]

		var leftSiblingState poseidon.PoseidonState
		copy(leftSiblingState[0:4], sibling[0:4])
		copy(leftSiblingState[4:8], currentDigest[0:4])
		copy(leftSiblingState[8:12], fourZeros[0:4])
		leftHash := f.poseidonChip.Poseidon(leftSiblingState)
		leftHashCompress := leftHash[0:4]

		var rightSiblingState poseidon.PoseidonState
		copy(rightSiblingState[0:4], currentDigest[0:4])
		copy(rightSiblingState[4:8], sibling[0:4])
		copy(rightSiblingState[8:12], fourZeros[0:4])
		rightHash := f.poseidonChip.Poseidon(rightSiblingState)
		rightHashCompress := rightHash[0:4]

		currentDigest = f.api.Select(bit, leftHashCompress, rightHashCompress).(Hash)
	}
}

func (f *FriChip) verifyInitialProof(xIndexBits []frontend.Variable, proof *FriInitialTreeProof, initialMerkleCaps []MerkleCap, capIndex F) {
	if len(proof.EvalsProofs) != len(initialMerkleCaps) {
		panic("length of eval proofs in fri proof should equal length of initial merkle caps")
	}

	for i := 0; i < len(initialMerkleCaps); i++ {
		evals := proof.EvalsProofs[i].Elements
		merkleProof := proof.EvalsProofs[i].MerkleProof
		cap := initialMerkleCaps[i]
		f.verifyMerkleProofToCapWithCapIndex(evals, xIndexBits, capIndex, cap, &merkleProof)
	}
}

// / We decompose FRI query indices into bits without verifying that the decomposition given by
// / the prover is the canonical one. In particular, if `x_index < 2^field_bits - p`, then the
// / prover could supply the binary encoding of either `x_index` or `x_index + p`, since they are
// / congruent mod `p`. However, this only occurs with probability
// /     p_ambiguous = (2^field_bits - p) / p
// / which is small for the field that we use in practice.
// /
// / In particular, the soundness error of one FRI query is roughly the codeword rate, which
// / is much larger than this ambiguous-element probability given any reasonable parameters.
// / Thus ambiguous elements contribute a negligible amount to soundness error.
// /
// / Here we compare the probabilities as a sanity check, to verify the claim above.
func (f *FriChip) assertNoncanonicalIndicesOK() {
	numAmbiguousElems := uint64(math.MaxUint64) - EmulatedFieldModulus().Uint64() + 1
	queryError := f.friParams.Config.rate()
	pAmbiguous := float64(numAmbiguousElems) / float64(EmulatedFieldModulus().Uint64())

	// TODO:  Check that pAmbiguous value is the same as the one in plonky2 verifier
	if pAmbiguous >= queryError*1e-5 {
		panic("A non-negligible portion of field elements are in the range that permits non-canonical encodings. Need to do more analysis or enforce canonical encodings.")
	}
}

func (f *FriChip) verifyQueryRound(
	challenges *FriChallenges,
	precomputedReducedEval []QuadraticExtension,
	initialMerkleCaps []MerkleCap,
	proof *FriProof,
	xIndex F,
	n uint64,
	nLog uint64,
	roundProof *FriQueryRound,
) {
	f.assertNoncanonicalIndicesOK()
	xIndexBits := f.qe.field.ToBinary(xIndex, int(nLog))
	capIndex := f.qe.field.FromBinary(xIndexBits[len(xIndexBits)-int(f.friParams.Config.CapHeight):]...).(F)

	f.verifyInitialProof(xIndexBits, &roundProof.InitialTreesProof, initialMerkleCaps, capIndex)
}

func (f *FriChip) VerifyFriProof(
	openings FriOpenings,
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
	f.assertLeadingZeros(friChallenges.FriPowResponse, f.friParams.Config)

	precomputedReducedEvals := f.fromOpeningsAndAlpha(&openings, friChallenges.FriAlpha)

	// Size of the LDE domain.
	nLog := f.friParams.DegreeBits + f.friParams.Config.RateBits
	n := uint64(math.Pow(2, float64(nLog)))

	if len(friChallenges.FriQueryIndicies) != len(friProof.QueryRoundProofs) {
		panic(fmt.Sprintf(
			"Number of query indices (%d) should equal number of query round proofs (%d)",
			len(friChallenges.FriQueryIndicies),
			len(friProof.QueryRoundProofs),
		))
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
			nLog,
			&roundProof,
		)
	}
}
