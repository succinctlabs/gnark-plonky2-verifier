package plonky2_verifier

import (
	"fmt"
	"gnark-ed25519/field"
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"
	"math"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
)

type FriChip struct {
	api      frontend.API
	fieldAPI frontend.API
	qeAPI    *QuadraticExtensionAPI

	poseidonChip *poseidon.PoseidonChip

	friParams               *FriParams
	verifierOnlyCircuitData *VerifierOnlyCircuitData
}

func NewFriChip(api frontend.API, fieldAPI frontend.API, qeAPI *QuadraticExtensionAPI, poseidonChip *poseidon.PoseidonChip, friParams *FriParams) *FriChip {
	return &FriChip{
		api:          api,
		fieldAPI:     fieldAPI,
		qeAPI:        qeAPI,
		poseidonChip: poseidonChip,
		friParams:    friParams,
	}
}

func (f *FriChip) assertLeadingZeros(powWitness F, friConfig FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least `leading_zeros` leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long
	maxPowWitness := uint64(math.Pow(2, float64(64-friConfig.ProofOfWorkBits))) - 1
	f.fieldAPI.AssertIsLessOrEqual(powWitness, field.NewFieldElement(maxPowWitness))
}

func (f *FriChip) fromOpeningsAndAlpha(openings *FriOpenings, alpha QuadraticExtension) []QuadraticExtension {
	// One reduced opening for all openings evaluated at point Zeta.
	// Another one for all openings evaluated at point Zeta * Omega (which is only PlonkZsNext polynomial)

	reducedOpenings := make([]QuadraticExtension, 0, 2)
	for _, batch := range openings.Batches {
		reducedOpenings = append(reducedOpenings, f.qeAPI.ReduceWithPowers(batch.values, alpha))
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
			elements[i] = field.ZERO_F
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

func (f *FriChip) verifyMerkleProofToCapWithCapIndex(leafData []F, leafIndexBits []frontend.Variable, capIndexBits []frontend.Variable, merkleCap MerkleCap, proof *MerkleProof) {
	currentDigest := f.hashOrNoop(leafData)
	fourZeros := [4]F{field.ZERO_F, field.ZERO_F, field.ZERO_F, field.ZERO_F}
	for i, sibling := range proof.Siblings {
		bit := leafIndexBits[i]

		var leftSiblingState poseidon.PoseidonState
		copy(leftSiblingState[0:4], sibling[0:4])
		copy(leftSiblingState[4:8], currentDigest[0:4])
		copy(leftSiblingState[8:12], fourZeros[0:4])

		leftHash := f.poseidonChip.Poseidon(leftSiblingState)
		var leftHashCompress Hash
		leftHashCompress[0] = leftHash[0]
		leftHashCompress[1] = leftHash[1]
		leftHashCompress[2] = leftHash[2]
		leftHashCompress[3] = leftHash[3]

		var rightSiblingState poseidon.PoseidonState
		copy(rightSiblingState[0:4], currentDigest[0:4])
		copy(rightSiblingState[4:8], sibling[0:4])
		copy(rightSiblingState[8:12], fourZeros[0:4])

		rightHash := f.poseidonChip.Poseidon(rightSiblingState)
		var rightHashCompress Hash
		rightHashCompress[0] = rightHash[0]
		rightHashCompress[1] = rightHash[1]
		rightHashCompress[2] = rightHash[2]
		rightHashCompress[3] = rightHash[3]

		currentDigest = SelectHash(f.fieldAPI, bit, leftHashCompress, rightHashCompress)
	}

	// We assume that the cap_height is 4.  Create two levels of the Lookup2 circuit
	if len(capIndexBits) != 4 || len(merkleCap) != 16 {
		panic("capIndexBits length should be 4 and the merkleCap length should be 16")
	}

	const NUM_LEAF_LOOKUPS = 4
	var leafLookups [NUM_LEAF_LOOKUPS]Hash
	// First create the "leaf" lookup2 circuits
	// The will use the least significant bits of the capIndexBits array
	for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
		leafLookups[i] = Lookup2Hash(
			f.fieldAPI, capIndexBits[0], capIndexBits[1],
			merkleCap[i*NUM_LEAF_LOOKUPS], merkleCap[i*NUM_LEAF_LOOKUPS+1], merkleCap[i*NUM_LEAF_LOOKUPS+2], merkleCap[i*NUM_LEAF_LOOKUPS+3],
		)
	}

	// Use the most 2 significant bits of the capIndexBits array for the "root" lookup
	merkleCapEntry := Lookup2Hash(f.fieldAPI, capIndexBits[2], capIndexBits[3], leafLookups[0], leafLookups[1], leafLookups[2], leafLookups[3])
	AssertIsEqualHash(f.fieldAPI, currentDigest, merkleCapEntry)
}

func (f *FriChip) verifyInitialProof(xIndexBits []frontend.Variable, proof *FriInitialTreeProof, initialMerkleCaps []MerkleCap, capIndexBits []frontend.Variable) {
	if len(proof.EvalsProofs) != len(initialMerkleCaps) {
		panic("length of eval proofs in fri proof should equal length of initial merkle caps")
	}

	for i := 0; i < len(initialMerkleCaps); i++ {
		evals := proof.EvalsProofs[i].Elements
		merkleProof := proof.EvalsProofs[i].MerkleProof
		cap := initialMerkleCaps[i]
		f.verifyMerkleProofToCapWithCapIndex(evals, xIndexBits, capIndexBits, cap, &merkleProof)
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
	numAmbiguousElems := uint64(math.MaxUint64) - goldilocks.Modulus().Uint64() + 1
	queryError := f.friParams.Config.rate()
	pAmbiguous := float64(numAmbiguousElems) / float64(goldilocks.Modulus().Uint64())

	// TODO:  Check that pAmbiguous value is the same as the one in plonky2 verifier
	if pAmbiguous >= queryError*1e-5 {
		panic("A non-negligible portion of field elements are in the range that permits non-canonical encodings. Need to do more analysis or enforce canonical encodings.")
	}
}

func (f *FriChip) expFromBitsConstBase(
	base goldilocks.Element,
	exponentBits []frontend.Variable,
) F {
	product := ONE_F
	for i, bit := range exponentBits {
		pow := int64(1 << i)
		// If the bit is on, we multiply product by base^pow.
		// We can arithmetize this as:
		//     product *= 1 + bit (base^pow - 1)
		//     product = (base^pow - 1) product bit + product
		basePow := goldilocks.NewElement(0)
		basePow.Exp(base, big.NewInt(pow))

		basePowElement := NewFieldElement(basePow.Uint64() - 1)

		product = f.fieldAPI.Add(
			f.fieldAPI.Mul(
				basePowElement,
				product,
				bit,
			),
			product,
		).(F)
	}

	return product
}

func (f *FriChip) calculateSubgroupX(
	xIndexBits []frontend.Variable,
	nLog uint64,
) F {
	// Compute x from its index
	// `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
	// TODO - Make these as global values
	g := field.NewFieldElement(field.GOLDILOCKS_MULTIPLICATIVE_GROUP_GENERATOR.Uint64())
	base := field.GoldilocksPrimitiveRootOfUnity(nLog)

	// Create a reverse list of xIndexBits
	xIndexBitsRev := make([]frontend.Variable, 0)
	for i := len(xIndexBits) - 1; i >= 0; i-- {
		xIndexBitsRev = append(xIndexBitsRev, xIndexBits[i])
	}

	product := f.expFromBitsConstBase(base, xIndexBitsRev)

	return f.fieldAPI.Mul(g, product).(F)
}

func (f *FriChip) friCombineInitial(
	instance FriInstanceInfo,
	proof FriInitialTreeProof,
	friAlpha QuadraticExtension,
	subgroupX_QE QuadraticExtension,
	precomputedReducedEval []QuadraticExtension,
) QuadraticExtension {
	sum := f.qeAPI.ZERO_QE

	if len(instance.Batches) != len(precomputedReducedEval) {
		panic("len(openings) != len(precomputedReducedEval)")
	}

	for i := 0; i < len(instance.Batches); i++ {
		batch := instance.Batches[i]
		reducedOpenings := precomputedReducedEval[i]

		point := batch.Point
		evals := make([]QuadraticExtension, 0)
		for _, polynomial := range batch.Polynomials {
			evals = append(
				evals,
				QuadraticExtension{proof.EvalsProofs[polynomial.OracleIndex].Elements[polynomial.PolynomialInfo], field.ZERO_F},
			)
		}

		reducedEvals := f.qeAPI.ReduceWithPowers(evals, friAlpha)
		numerator := f.qeAPI.SubExtension(reducedEvals, reducedOpenings)
		denominator := f.qeAPI.SubExtension(subgroupX_QE, point)
		sum = f.qeAPI.MulExtension(f.qeAPI.ExpU64Extension(friAlpha, uint64(len(evals))), sum)
		sum = f.qeAPI.AddExtension(
			f.qeAPI.DivExtension(
				numerator,
				denominator,
			),
			sum,
		)
	}

	return f.qeAPI.MulExtension(sum, subgroupX_QE)
}

func (f *FriChip) finalPolyEval(finalPoly PolynomialCoeffs, point QuadraticExtension) QuadraticExtension {
	ret := f.qeAPI.ZERO_QE
	for i := len(finalPoly.Coeffs) - 1; i >= 0; i-- {
		ret = f.qeAPI.AddExtension(
			f.qeAPI.MulExtension(
				ret,
				point,
			),
			finalPoly.Coeffs[i],
		)
	}
	return ret
}

func (f *FriChip) interpolate(x QuadraticExtension, xPoints []QuadraticExtension, yPoints []QuadraticExtension, barycentricWeights []QuadraticExtension) QuadraticExtension {
	if len(xPoints) != len(yPoints) || len(xPoints) != len(barycentricWeights) {
		panic("length of xPoints, yPoints, and barycentricWeights are inconsistent")
	}

	lX := f.qeAPI.ONE_QE
	for i := 0; i < len(xPoints); i++ {
		lX = f.qeAPI.MulExtension(
			lX,
			f.qeAPI.SubExtension(
				x,
				xPoints[i],
			),
		)
	}

	sum := f.qeAPI.ZERO_QE
	for i := 0; i < len(xPoints); i++ {
		sum = f.qeAPI.AddExtension(
			f.qeAPI.MulExtension(
				f.qeAPI.DivExtension(
					barycentricWeights[i],
					f.qeAPI.SubExtension(
						x,
						xPoints[i],
					),
				),
				yPoints[i],
			),
			sum,
		)
	}

	interpolation := f.qeAPI.MulExtension(lX, sum)

	returnField := interpolation
	// Now check if x is already within the xPoints
	for i := 0; i < len(xPoints); i++ {
		returnField = f.qeAPI.Select(
			f.qeAPI.IsZero(f.qeAPI.SubExtension(x, xPoints[i])),
			yPoints[i],
			returnField,
		)
	}

	return returnField
}

func (f *FriChip) computeEvaluation(
	x F,
	xIndexWithinCosetBits []frontend.Variable,
	arityBits uint64,
	evals []QuadraticExtension,
	beta QuadraticExtension,
) QuadraticExtension {
	arity := 1 << arityBits
	if (len(evals)) != arity {
		panic("len(evals) ! arity")
	}
	if arityBits > 8 {
		panic("currently assuming that arityBits is <= 8")
	}

	g := field.GoldilocksPrimitiveRootOfUnity(arityBits)
	gInv := goldilocks.NewElement(0)
	gInv.Exp(g, big.NewInt(int64(arity-1)))

	// The evaluation vector needs to be reordered first.  Permute the evals array such that each
	// element's new index is the bit reverse of it's original index.
	// TODO:  Optimization - Since the size of the evals array should be constant (e.g. 2^arityBits),
	//        we can just hard code the permutation.
	permutedEvals := make([]QuadraticExtension, len(evals))
	for i := uint8(0); i < uint8(len(evals)); i++ {
		newIndex := bits.Reverse8(i) >> arityBits
		permutedEvals[newIndex] = evals[i]
	}

	// Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
	// as `(g^-1)^rev_x_index_within_coset`.
	revXIndexWithinCosetBits := make([]frontend.Variable, len(xIndexWithinCosetBits))
	for i := 0; i < len(xIndexWithinCosetBits); i++ {
		revXIndexWithinCosetBits[len(xIndexWithinCosetBits)-1-i] = xIndexWithinCosetBits[i]
	}
	start := f.expFromBitsConstBase(gInv, revXIndexWithinCosetBits)
	cosetStart := f.fieldAPI.Mul(start, x).(F)

	xPoints := make([]QuadraticExtension, len(evals))
	yPoints := permutedEvals

	// TODO: Make g_F a constant
	g_F := f.qeAPI.FieldToQE(NewFieldElement(g.Uint64()))
	xPoints[0] = f.qeAPI.FieldToQE(cosetStart)
	for i := 1; i < len(evals); i++ {
		xPoints[i] = f.qeAPI.MulExtension(xPoints[i-1], g_F)
	}

	// TODO:  This is n^2.  Is there a way to do this better?
	// Compute the barycentric weights
	barycentricWeights := make([]QuadraticExtension, len(xPoints))
	for i := 0; i < len(xPoints); i++ {
		barycentricWeights[i] = f.qeAPI.ONE_QE
		for j := 0; j < len(xPoints); j++ {
			if i != j {
				barycentricWeights[i] = f.qeAPI.MulExtension(
					f.qeAPI.SubExtension(xPoints[i], xPoints[j]),
					barycentricWeights[i],
				)
			}
		}
		// Take the inverse of the barycentric weights
		// TODO: Can provide a witness to this value
		barycentricWeights[i] = f.qeAPI.InverseExtension(barycentricWeights[i])
	}

	return f.interpolate(beta, xPoints, yPoints, barycentricWeights)
}

func (f *FriChip) verifyQueryRound(
	instance FriInstanceInfo,
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
	xIndexBits := f.fieldAPI.ToBinary(xIndex, int(nLog))
	capIndexBits := xIndexBits[len(xIndexBits)-int(f.friParams.Config.CapHeight):]

	f.verifyInitialProof(xIndexBits, &roundProof.InitialTreesProof, initialMerkleCaps, capIndexBits)

	subgroupX := f.calculateSubgroupX(
		xIndexBits,
		nLog,
	)

	subgroupX_QE := QuadraticExtension{subgroupX, field.ZERO_F}

	oldEval := f.friCombineInitial(
		instance,
		roundProof.InitialTreesProof,
		challenges.FriAlpha,
		subgroupX_QE,
		precomputedReducedEval,
	)

	for i, arityBits := range f.friParams.ReductionArityBits {
		evals := roundProof.Steps[i].Evals

		cosetIndexBits := xIndexBits[arityBits:]
		xIndexWithinCosetBits := xIndexBits[:arityBits]

		// Assumes that the arity bits will be 4.  That means that the range of
		// xIndexWithCoset is [0,2^4-1].  This is based on plonky2's circuit recursive
		// config:  https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/plonk/circuit_data.rs#L63
		// Will use a two levels tree of 4-selector gadgets.
		if arityBits != 4 {
			panic("assuming arity bits is 4")
		}

		const NUM_LEAF_LOOKUPS = 4
		var leafLookups [NUM_LEAF_LOOKUPS]QuadraticExtension
		// First create the "leaf" lookup2 circuits
		// The will use the least significant bits of the xIndexWithCosetBits array
		for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
			leafLookups[i] = f.qeAPI.Lookup2(
				xIndexWithinCosetBits[0],
				xIndexWithinCosetBits[1],
				evals[i*NUM_LEAF_LOOKUPS],
				evals[i*NUM_LEAF_LOOKUPS+1],
				evals[i*NUM_LEAF_LOOKUPS+2],
				evals[i*NUM_LEAF_LOOKUPS+3],
			)
		}

		// Use the most 2 significant bits of the xIndexWithCosetBits array for the "root" lookup
		newEval := f.qeAPI.Lookup2(
			xIndexWithinCosetBits[2],
			xIndexWithinCosetBits[3],
			leafLookups[0],
			leafLookups[1],
			leafLookups[2],
			leafLookups[3],
		)

		f.qeAPI.AssertIsEqual(newEval, oldEval)

		oldEval = f.computeEvaluation(
			subgroupX,
			xIndexWithinCosetBits,
			arityBits,
			evals,
			challenges.FriBetas[i],
		)

		// Convert evals (array of QE) to fields by taking their 0th degree coefficients
		fieldEvals := make([]F, 0, 2*len(evals))
		for j := 0; j < len(evals); j++ {
			fieldEvals = append(fieldEvals, evals[j][0])
			fieldEvals = append(fieldEvals, evals[j][1])
		}
		f.verifyMerkleProofToCapWithCapIndex(
			fieldEvals,
			cosetIndexBits,
			capIndexBits,
			proof.CommitPhaseMerkleCaps[i],
			&roundProof.Steps[i].MerkleProof,
		)

		// Update the point x to x^arity.
		for j := uint64(0); j < arityBits; j++ {
			subgroupX = f.fieldAPI.Mul(subgroupX, subgroupX).(F)
		}

		xIndexBits = cosetIndexBits
	}

	subgroupX_QE = f.qeAPI.FieldToQE(subgroupX)
	finalPolyEval := f.finalPolyEval(proof.FinalPoly, subgroupX_QE)

	f.qeAPI.AssertIsEqual(oldEval, finalPolyEval)
}

func (f *FriChip) VerifyFriProof(
	instance FriInstanceInfo,
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
			instance,
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
