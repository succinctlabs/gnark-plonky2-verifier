package fri

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type Chip struct {
	api               frontend.API `gnark:"-"`
	gl                gl.Chip      `gnark:"-"`
	poseidonBN254Chip *poseidon.BN254Chip
	friParams         *types.FriParams `gnark:"-"`
}

func NewChip(
	api frontend.API,
	friParams *types.FriParams,
) *Chip {
	poseidonBN254Chip := poseidon.NewBN254Chip(api)
	return &Chip{
		api:               api,
		poseidonBN254Chip: poseidonBN254Chip,
		friParams:         friParams,
		gl:                *gl.New(api),
	}
}

func (f *Chip) assertLeadingZeros(powWitness gl.Variable, friConfig types.FriConfig) {
	// Asserts that powWitness'es big-endian bit representation has at least `leading_zeros` leading zeros.
	// Note that this is assuming that the Goldilocks field is being used.  Specfically that the
	// field is 64 bits long
	maxPowWitness := uint64(math.Pow(2, float64(64-friConfig.ProofOfWorkBits))) - 1
	reducedPowWitness := f.gl.Reduce(powWitness)
	f.api.AssertIsLessOrEqual(reducedPowWitness.Limb, frontend.Variable(maxPowWitness))
}

func (f *Chip) fromOpeningsAndAlpha(
	openings *Openings,
	alpha gl.QuadraticExtensionVariable,
) []gl.QuadraticExtensionVariable {
	// One reduced opening for all openings evaluated at point Zeta.
	// Another one for all openings evaluated at point Zeta * Omega (which is only PlonkZsNext polynomial)

	reducedOpenings := make([]gl.QuadraticExtensionVariable, 0, 2)
	for _, batch := range openings.Batches {
		reducedOpenings = append(reducedOpenings, f.gl.ReduceWithPowers(batch.Values, alpha))
	}

	return reducedOpenings
}

func (f *Chip) verifyMerkleProofToCapWithCapIndex(
	leafData []gl.Variable,
	leafIndexBits []frontend.Variable,
	capIndexBits []frontend.Variable,
	merkleCap variables.FriMerkleCap,
	proof *variables.FriMerkleProof,
) {
	currentDigest := f.poseidonBN254Chip.HashOrNoop(leafData)
	for i, sibling := range proof.Siblings {
		bit := leafIndexBits[i]
		// TODO: Don't need to do two hashes by using a trick that the plonky2 verifier circuit does
		// https://github.com/mir-protocol/plonky2/blob/973624f12d2d12d74422b3ea051358b9eaacb050/plonky2/src/gates/poseidon.rs#L298
		leftHash := f.poseidonBN254Chip.TwoToOne(sibling, currentDigest)
		rightHash := f.poseidonBN254Chip.TwoToOne(currentDigest, sibling)
		currentDigest = f.api.Select(bit, leftHash, rightHash)
	}

	// We assume that the cap_height is 4.  Create two levels of the Lookup2 circuit
	if len(capIndexBits) != 4 || len(merkleCap) != 16 {
		errorMsg, _ := fmt.Printf(
			"capIndexBits length should be 4 and the merkleCap length should be 16.  Actual values (capIndexBits: %d, merkleCap: %d)\n",
			len(capIndexBits),
			len(merkleCap),
		)
		panic(errorMsg)
	}

	const NUM_LEAF_LOOKUPS = 4
	var leafLookups [NUM_LEAF_LOOKUPS]poseidon.BN254HashOut
	// First create the "leaf" lookup2 circuits
	// The will use the least significant bits of the capIndexBits array
	for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
		leafLookups[i] = f.api.Lookup2(
			capIndexBits[0], capIndexBits[1],
			merkleCap[i*NUM_LEAF_LOOKUPS], merkleCap[i*NUM_LEAF_LOOKUPS+1], merkleCap[i*NUM_LEAF_LOOKUPS+2], merkleCap[i*NUM_LEAF_LOOKUPS+3],
		)
	}

	// Use the most 2 significant bits of the capIndexBits array for the "root" lookup
	merkleCapEntry := f.api.Lookup2(capIndexBits[2], capIndexBits[3], leafLookups[0], leafLookups[1], leafLookups[2], leafLookups[3])
	f.api.AssertIsEqual(currentDigest, merkleCapEntry)
}

func (f *Chip) verifyInitialProof(xIndexBits []frontend.Variable, proof *variables.FriInitialTreeProof, initialMerkleCaps []variables.FriMerkleCap, capIndexBits []frontend.Variable) {
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
func (f *Chip) assertNoncanonicalIndicesOK() {
	numAmbiguousElems := uint64(math.MaxUint64) - goldilocks.Modulus().Uint64() + 1
	queryError := f.friParams.Config.Rate()
	pAmbiguous := float64(numAmbiguousElems) / float64(goldilocks.Modulus().Uint64())

	// TODO:  Check that pAmbiguous value is the same as the one in plonky2 verifier
	if pAmbiguous >= queryError*1e-5 {
		panic("A non-negligible portion of field elements are in the range that permits non-canonical encodings. Need to do more analysis or enforce canonical encodings.")
	}
}

func (f *Chip) expFromBitsConstBase(
	base goldilocks.Element,
	exponentBits []frontend.Variable,
) gl.Variable {
	product := gl.One()
	for i, bit := range exponentBits {
		// If the bit is on, we multiply product by base^pow.
		// We can arithmetize this as:
		//     product *= 1 + bit (base^pow - 1)
		//     product = (base^pow - 1) product bit + product
		pow := int64(1 << i)
		basePow := goldilocks.NewElement(0)
		basePow.Exp(base, big.NewInt(pow))
		basePowVariable := gl.NewVariable(basePow.Uint64() - 1)
		product = f.gl.Add(
			f.gl.Mul(
				f.gl.Mul(
					basePowVariable,
					product,
				),
				gl.NewVariable(bit),
			),
			product,
		)
	}
	return product
}

func (f *Chip) calculateSubgroupX(
	xIndexBits []frontend.Variable,
	nLog uint64,
) gl.Variable {
	// Compute x from its index
	// `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
	// TODO - Make these as global values
	g := gl.NewVariable(gl.MULTIPLICATIVE_GROUP_GENERATOR.Uint64())
	base := gl.PrimitiveRootOfUnity(nLog)

	// Create a reverse list of xIndexBits
	xIndexBitsRev := make([]frontend.Variable, 0)
	for i := len(xIndexBits) - 1; i >= 0; i-- {
		xIndexBitsRev = append(xIndexBitsRev, xIndexBits[i])
	}

	product := f.expFromBitsConstBase(base, xIndexBitsRev)

	return f.gl.Mul(g, product)
}

func (f *Chip) friCombineInitial(
	instance InstanceInfo,
	proof variables.FriInitialTreeProof,
	friAlpha gl.QuadraticExtensionVariable,
	subgroupX_QE gl.QuadraticExtensionVariable,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	sum := gl.ZeroExtension()

	if len(instance.Batches) != len(precomputedReducedEval) {
		panic("len(openings) != len(precomputedReducedEval)")
	}

	for i := 0; i < len(instance.Batches); i++ {
		batch := instance.Batches[i]
		reducedOpenings := precomputedReducedEval[i]

		point := batch.Point
		evals := make([]gl.QuadraticExtensionVariable, 0)
		for _, polynomial := range batch.Polynomials {
			evals = append(
				evals,
				gl.QuadraticExtensionVariable{
					proof.EvalsProofs[polynomial.OracleIndex].Elements[polynomial.PolynomialInfo],
					gl.Zero(),
				},
			)
		}

		reducedEvals := f.gl.ReduceWithPowers(evals, friAlpha)
		numerator := f.gl.SubExtensionNoReduce(reducedEvals, reducedOpenings)
		denominator := f.gl.SubExtension(subgroupX_QE, point)
		sum = f.gl.MulExtension(f.gl.ExpExtension(friAlpha, uint64(len(evals))), sum)
		sum = f.gl.MulAddExtension(
			numerator,
			f.gl.InverseExtension(denominator),
			sum,
		)
	}

	return sum
}

func (f *Chip) finalPolyEval(finalPoly variables.PolynomialCoeffs, point gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	ret := gl.ZeroExtension()
	for i := len(finalPoly.Coeffs) - 1; i >= 0; i-- {
		ret = f.gl.MulAddExtension(ret, point, finalPoly.Coeffs[i])
	}
	return ret
}

func (f *Chip) interpolate(
	x gl.QuadraticExtensionVariable,
	xPoints []gl.QuadraticExtensionVariable,
	yPoints []gl.QuadraticExtensionVariable,
	barycentricWeights []gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	if len(xPoints) != len(yPoints) || len(xPoints) != len(barycentricWeights) {
		panic("length of xPoints, yPoints, and barycentricWeights are inconsistent")
	}

	lX := gl.OneExtension()
	for i := 0; i < len(xPoints); i++ {
		lX = f.gl.SubMulExtension(x, xPoints[i], lX)
	}

	sum := gl.ZeroExtension()
	for i := 0; i < len(xPoints); i++ {
		sum = f.gl.AddExtension(
			f.gl.MulExtension(
				f.gl.DivExtension(
					barycentricWeights[i],
					f.gl.SubExtension(
						x,
						xPoints[i],
					),
				),
				yPoints[i],
			),
			sum,
		)
	}

	interpolation := f.gl.MulExtension(lX, sum)

	returnField := interpolation
	// Now check if x is already within the xPoints
	for i := 0; i < len(xPoints); i++ {
		returnField = f.gl.Lookup(
			f.gl.IsZero(f.gl.SubExtension(x, xPoints[i])),
			returnField,
			yPoints[i],
		)
	}

	return returnField
}

func (f *Chip) computeEvaluation(
	x gl.Variable,
	xIndexWithinCosetBits []frontend.Variable,
	arityBits uint64,
	evals []gl.QuadraticExtensionVariable,
	beta gl.QuadraticExtensionVariable,
) gl.QuadraticExtensionVariable {
	arity := 1 << arityBits
	if (len(evals)) != arity {
		panic("len(evals) ! arity")
	}
	if arityBits > 8 {
		panic("currently assuming that arityBits is <= 8")
	}

	g := gl.PrimitiveRootOfUnity(arityBits)
	gInv := goldilocks.NewElement(0)
	gInv.Exp(g, big.NewInt(int64(arity-1)))

	// The evaluation vector needs to be reordered first.  Permute the evals array such that each
	// element's new index is the bit reverse of it's original index.
	// TODO:  Optimization - Since the size of the evals array should be constant (e.g. 2^arityBits),
	//        we can just hard code the permutation.
	permutedEvals := make([]gl.QuadraticExtensionVariable, len(evals))
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
	cosetStart := f.gl.Mul(start, x)

	xPoints := make([]gl.QuadraticExtensionVariable, len(evals))
	yPoints := permutedEvals

	// TODO: Make g_F a constant
	g_F := gl.NewVariable(g.Uint64()).ToQuadraticExtension()
	xPoints[0] = gl.QuadraticExtensionVariable{cosetStart, gl.Zero()}
	for i := 1; i < len(evals); i++ {
		xPoints[i] = f.gl.MulExtension(xPoints[i-1], g_F)
	}

	// TODO:  This is n^2.  Is there a way to do this better?
	// Compute the barycentric weights
	barycentricWeights := make([]gl.QuadraticExtensionVariable, len(xPoints))
	for i := 0; i < len(xPoints); i++ {
		barycentricWeights[i] = gl.OneExtension()
		for j := 0; j < len(xPoints); j++ {
			if i != j {
				barycentricWeights[i] = f.gl.SubMulExtension(
					xPoints[i],
					xPoints[j],
					barycentricWeights[i],
				)
			}
		}
		// Take the inverse of the barycentric weights
		// TODO: Can provide a witness to this value
		barycentricWeights[i] = f.gl.InverseExtension(barycentricWeights[i])
	}

	return f.interpolate(beta, xPoints, yPoints, barycentricWeights)
}

func (f *Chip) verifyQueryRound(
	instance InstanceInfo,
	challenges *variables.FriChallenges,
	precomputedReducedEval []gl.QuadraticExtensionVariable,
	initialMerkleCaps []variables.FriMerkleCap,
	proof *variables.FriProof,
	xIndex gl.Variable,
	n uint64,
	nLog uint64,
	roundProof *variables.FriQueryRound,
) {
	f.assertNoncanonicalIndicesOK()
	xIndex = f.gl.Reduce(xIndex)
	xIndexBits := f.api.ToBinary(xIndex.Limb, 64)[0 : f.friParams.DegreeBits+f.friParams.Config.RateBits]
	capIndexBits := xIndexBits[len(xIndexBits)-int(f.friParams.Config.CapHeight):]

	f.verifyInitialProof(xIndexBits, &roundProof.InitialTreesProof, initialMerkleCaps, capIndexBits)

	subgroupX := f.calculateSubgroupX(
		xIndexBits,
		nLog,
	)

	subgroupX_QE := subgroupX.ToQuadraticExtension()

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
		var leafLookups [NUM_LEAF_LOOKUPS]gl.QuadraticExtensionVariable
		// First create the "leaf" lookup2 circuits
		// The will use the least significant bits of the xIndexWithCosetBits array
		for i := 0; i < NUM_LEAF_LOOKUPS; i++ {
			leafLookups[i] = f.gl.Lookup2(
				xIndexWithinCosetBits[0],
				xIndexWithinCosetBits[1],
				evals[i*NUM_LEAF_LOOKUPS],
				evals[i*NUM_LEAF_LOOKUPS+1],
				evals[i*NUM_LEAF_LOOKUPS+2],
				evals[i*NUM_LEAF_LOOKUPS+3],
			)
		}

		// Use the most 2 significant bits of the xIndexWithCosetBits array for the "root" lookup
		newEval := f.gl.Lookup2(
			xIndexWithinCosetBits[2],
			xIndexWithinCosetBits[3],
			leafLookups[0],
			leafLookups[1],
			leafLookups[2],
			leafLookups[3],
		)

		f.gl.AssertIsEqual(newEval[0], oldEval[0])
		f.gl.AssertIsEqual(newEval[1], oldEval[1])

		oldEval = f.computeEvaluation(
			subgroupX,
			xIndexWithinCosetBits,
			arityBits,
			evals,
			challenges.FriBetas[i],
		)

		// Convert evals (array of QE) to fields by taking their 0th degree coefficients
		fieldEvals := make([]gl.Variable, 0, 2*len(evals))
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
			subgroupX = f.gl.Mul(subgroupX, subgroupX)
		}

		xIndexBits = cosetIndexBits
	}

	subgroupX_QE = subgroupX.ToQuadraticExtension()
	finalPolyEval := f.finalPolyEval(proof.FinalPoly, subgroupX_QE)

	f.gl.AssertIsEqual(oldEval[0], finalPolyEval[0])
	f.gl.AssertIsEqual(oldEval[1], finalPolyEval[1])
}

func (f *Chip) VerifyFriProof(
	instance InstanceInfo,
	openings Openings,
	friChallenges *variables.FriChallenges,
	initialMerkleCaps []variables.FriMerkleCap,
	friProof *variables.FriProof,
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

	if len(friChallenges.FriQueryIndices) != len(friProof.QueryRoundProofs) {
		panic(fmt.Sprintf(
			"Number of query indices (%d) should equal number of query round proofs (%d)",
			len(friChallenges.FriQueryIndices),
			len(friProof.QueryRoundProofs),
		))
	}

	for idx, xIndex := range friChallenges.FriQueryIndices {
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
