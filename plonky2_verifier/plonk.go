package plonky2_verifier

import (
	. "gnark-ed25519/field"

	"github.com/consensys/gnark/frontend"
)

type PlonkChip struct {
	api   frontend.API
	field frontend.API
	qe    *QuadraticExtensionAPI

	commonData      CommonCircuitData
	proofChallenges ProofChallenges
	openings        OpeningSet
}

func (p *PlonkChip) expPowerOf2Extension(x QuadraticExtension) QuadraticExtension {
	for i := uint64(0); i < p.commonData.DegreeBits; i++ {
		x = p.qe.SquareExtension(x)
	}

	return x
}

func (p *PlonkChip) evalL0(x QuadraticExtension, xPowN QuadraticExtension) QuadraticExtension {
	// L_0(x) = (x^n - 1) / (n * (x - 1))
	eval_zero_poly := p.qe.SubExtension(
		xPowN,
		p.qe.ONE,
	)
	denominator := p.qe.SubExtension(
		p.qe.ScalarMulExtension(x, p.qe.DEGREE_BITS_F),
		p.qe.DEGREE_BITS_QE,
	)
	return p.qe.DivExtension(
		eval_zero_poly,
		denominator,
	)
}

func (p *PlonkChip) checkPartialProducts(
	numerators []QuadraticExtension,
	denominators []QuadraticExtension,
	challengeNum uint64) []QuadraticExtension {

	numPartProds := p.commonData.NumPartialProducts
	quotDegreeFactor := p.commonData.QuotientDegreeFactor

	productAccs := make([]QuadraticExtension, numPartProds+2)
	productAccs = append(productAccs, p.openings.PlonkZs[challengeNum])
	productAccs = append(productAccs, p.openings.PartialProducts[challengeNum*numPartProds:(challengeNum+1)*numPartProds]...)
	productAccs = append(productAccs, p.openings.PlonkZsNext[challengeNum])

	partialProductChecks := make([]QuadraticExtension, numPartProds)

	for i := uint64(0); i < numPartProds; i += 1 {
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

func (p *PlonkChip) evalVanishingPoly() []QuadraticExtension {
	// Calculate the k[i] * x
	s_ids := make([]QuadraticExtension, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		p.qe.ScalarMulExtension(p.proofChallenges.PlonkZeta, p.commonData.KIs[i])
	}

	// Calculate zeta^n
	zeta_pow_n := p.expPowerOf2Extension(p.proofChallenges.PlonkZeta)

	// Calculate L_0(zeta)
	l_0_zeta := p.evalL0(p.proofChallenges.PlonkZeta, zeta_pow_n)

	vanishing_z1_terms := make([]QuadraticExtension, p.commonData.Config.NumChallenges)
	vanishing_partial_products_terms := make([]QuadraticExtension, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	numerator_values := make([]QuadraticExtension, p.commonData.Config.NumChallenges*p.commonData.Config.NumRoutedWires)
	denominator_values := make([]QuadraticExtension, p.commonData.Config.NumChallenges*p.commonData.Config.NumRoutedWires)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := p.qe.SubExtension(
			p.qe.MulExtension(l_0_zeta, p.openings.PlonkZs[i]),
			l_0_zeta,
		)
		vanishing_z1_terms = append(vanishing_z1_terms, z1_term)

		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.
			wire_value_plus_gamma := p.qe.AddExtension(
				p.openings.Wires[j],
				p.qe.FieldToQE(p.proofChallenges.PlonkGammas[i]),
			)
			numerator := p.qe.AddExtension(
				p.qe.MulExtension(
					p.qe.FieldToQE(p.proofChallenges.PlonkBetas[i]),
					s_ids[j],
				),
				wire_value_plus_gamma,
			)

			denominator := p.qe.AddExtension(
				p.qe.MulExtension(
					p.qe.FieldToQE(p.proofChallenges.PlonkBetas[i]),
					p.openings.PlonkSigmas[j],
				),
				wire_value_plus_gamma,
			)

			numerator_values = append(numerator_values, numerator)
			denominator_values = append(denominator_values, denominator)
		}

		vanishing_partial_products_terms = append(
			vanishing_partial_products_terms,
			p.checkPartialProducts(numerator_values, denominator_values, i)...,
		)
	}

	return vanishing_partial_products_terms
}

func (p *PlonkChip) Verify() {
	p.evalVanishingPoly()
}
