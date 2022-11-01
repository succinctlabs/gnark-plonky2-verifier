package plonky2_verifier

import (
	. "gnark-ed25519/field"

	"github.com/consensys/gnark/frontend"
)

type PlonkChip struct {
	api frontend.API
	qe  *QuadraticExtensionAPI

	commonData      CommonCircuitData
	proofChallenges ProofChallenges
	openings        OpeningSet

	DEGREE        F
	DEGREE_BITS_F F
	DEGREE_QE     QuadraticExtension
}

func NewPlonkChip(api frontend.API, qe *QuadraticExtensionAPI, commonData CommonCircuitData) *PlonkChip {
	// TODO:  Should degreeBits be verified that it fits within the field and that degree is within uint64?

	return &PlonkChip{
		api: api,
		qe:  qe,

		commonData: commonData,

		DEGREE:        NewFieldElement(1 << commonData.DegreeBits),
		DEGREE_BITS_F: NewFieldElement(commonData.DegreeBits),
		DEGREE_QE:     QuadraticExtension{NewFieldElement(1 << commonData.DegreeBits), NewFieldElement(0)},
	}
}

func (p *PlonkChip) expPowerOf2Extension(x QuadraticExtension) QuadraticExtension {
	for i := uint64(0); i < p.commonData.DegreeBits; i++ {
		x = p.qe.SquareExtension(x)
	}

	return x
}

func (p *PlonkChip) evalL0(x QuadraticExtension, xPowN QuadraticExtension) QuadraticExtension {
	// L_0(x) = (x^n - 1) / (n * (x - 1))
	evalZeroPoly := p.qe.SubExtension(
		xPowN,
		p.qe.ONE,
	)
	denominator := p.qe.SubExtension(
		p.qe.ScalarMulExtension(x, p.DEGREE),
		p.DEGREE_QE,
	)
	return p.qe.DivExtension(
		evalZeroPoly,
		denominator,
	)
}

func (p *PlonkChip) checkPartialProducts(
	numerators []QuadraticExtension,
	denominators []QuadraticExtension,
	challengeNum uint64,
) []QuadraticExtension {
	numPartProds := p.commonData.NumPartialProducts
	quotDegreeFactor := p.commonData.QuotientDegreeFactor

	productAccs := make([]QuadraticExtension, 0, numPartProds+2)
	productAccs = append(productAccs, p.openings.PlonkZs[challengeNum])
	productAccs = append(productAccs, p.openings.PartialProducts[challengeNum*numPartProds:(challengeNum+1)*numPartProds]...)
	productAccs = append(productAccs, p.openings.PlonkZsNext[challengeNum])

	partialProductChecks := make([]QuadraticExtension, 0, numPartProds)

	for i := uint64(0); i <= numPartProds; i += 1 {
		ppStartIdx := i * quotDegreeFactor
		numeProduct := numerators[ppStartIdx]
		denoProduct := denominators[ppStartIdx]
		for j := uint64(1); j < quotDegreeFactor; j++ {
			numeProduct = p.qe.MulExtension(numeProduct, numerators[ppStartIdx+j])
			denoProduct = p.qe.MulExtension(denoProduct, denominators[ppStartIdx+j])
		}

		partialProductCheck := p.qe.SubExtension(
			p.qe.MulExtension(productAccs[i], numeProduct),
			p.qe.MulExtension(productAccs[i+1], denoProduct),
		)

		partialProductChecks = append(partialProductChecks, partialProductCheck)
	}
	return partialProductChecks
}

func (p *PlonkChip) evalVanishingPoly(zetaPowN QuadraticExtension) []QuadraticExtension {
	// Calculate the k[i] * x
	sIDs := make([]QuadraticExtension, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = p.qe.ScalarMulExtension(p.proofChallenges.PlonkZeta, p.commonData.KIs[i])
	}

	// Calculate L_0(zeta)
	l0Zeta := p.evalL0(p.proofChallenges.PlonkZeta, zetaPowN)

	vanishingZ1Terms := make([]QuadraticExtension, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]QuadraticExtension, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := p.qe.MulExtension(
			l0Zeta,
			p.qe.SubExtension(p.openings.PlonkZs[i], p.qe.ONE))
		vanishingZ1Terms = append(vanishingZ1Terms, z1_term)

		numeratorValues := make([]QuadraticExtension, 0, p.commonData.Config.NumRoutedWires)
		denominatorValues := make([]QuadraticExtension, 0, p.commonData.Config.NumRoutedWires)
		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.

			wireValuePlusGamma := p.qe.AddExtension(
				p.openings.Wires[j],
				p.qe.FieldToQE(p.proofChallenges.PlonkGammas[i]),
			)

			numerator := p.qe.AddExtension(
				p.qe.MulExtension(
					p.qe.FieldToQE(p.proofChallenges.PlonkBetas[i]),
					sIDs[j],
				),
				wireValuePlusGamma,
			)

			denominator := p.qe.AddExtension(
				p.qe.MulExtension(
					p.qe.FieldToQE(p.proofChallenges.PlonkBetas[i]),
					p.openings.PlonkSigmas[j],
				),
				wireValuePlusGamma,
			)

			numeratorValues = append(numeratorValues, numerator)
			denominatorValues = append(denominatorValues, denominator)
		}

		vanishingPartialProductsTerms = append(
			vanishingPartialProductsTerms,
			p.checkPartialProducts(numeratorValues, denominatorValues, i)...,
		)
	}

	vanishingTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)

	reducedValues := make([]QuadraticExtension, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		reducedValues[i] = p.qe.ZERO_QE
	}

	// TODO:  Enable this check once the custom gate evaluations are added to the
	//        vanishingTerms array
	/*
		if len(vanishingTerms) != int(p.commonData.QuotientDegreeFactor) {
			panic("evalVanishingPoly: len(vanishingTerms) != int(p.commonData.QuotientDegreeFactor)")
		}
	*/

	// reverse iterate the vanishingPartialProductsTerms array
	for i := len(vanishingTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			reducedValues[j] = p.qe.AddExtension(
				vanishingTerms[i],
				p.qe.ScalarMulExtension(
					reducedValues[j],
					p.proofChallenges.PlonkAlphas[j],
				),
			)
		}
	}

	return reducedValues
}

func (p *PlonkChip) reduceWithPowers(terms []QuadraticExtension, scalar QuadraticExtension) QuadraticExtension {
	sum := p.qe.ZERO_QE

	for i := len(terms) - 1; i >= 0; i-- {
		sum = p.qe.AddExtension(
			p.qe.MulExtension(
				sum,
				scalar,
			),
			terms[i],
		)
	}

	return sum
}

func (p *PlonkChip) Verify() {
	// Calculate zeta^n
	zetaPowN := p.expPowerOf2Extension(p.proofChallenges.PlonkZeta)

	vanishingPolysZeta := p.evalVanishingPoly(zetaPowN)

	// Calculate Z(H)
	zHZeta := p.qe.SubExtension(zetaPowN, p.qe.ONE)

	// `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
	// Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
	// where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
	// So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
	// `quotient_degree_factor`-sized chunk of the original evaluations.
	for i := 0; i < len(p.openings.QuotientPolys); i += int(p.commonData.QuotientDegreeFactor) {
		prod := p.qe.MulExtension(
			zHZeta,
			p.reduceWithPowers(
				p.openings.QuotientPolys[i:i+int(p.commonData.QuotientDegreeFactor)],
				zetaPowN,
			),
		)

		// TODO: Uncomment this after adding in the custom gates evaluations
		//p.api.AssertIsEqual(vanishingPolysZeta[i], prod)
	}
}
