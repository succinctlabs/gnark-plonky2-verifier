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
	evalZeroPoly := p.qe.SubExtension(
		xPowN,
		p.qe.ONE,
	)
	denominator := p.qe.SubExtension(
		p.qe.ScalarMulExtension(x, p.qe.DEGREE_BITS_F),
		p.qe.DEGREE_BITS_QE,
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
	sIDs := make([]QuadraticExtension, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = p.qe.ScalarMulExtension(p.proofChallenges.PlonkZeta, p.commonData.KIs[i])
	}

	// Calculate zeta^n
	zetaPowN := p.expPowerOf2Extension(p.proofChallenges.PlonkZeta)

	// Calculate L_0(zeta)
	l0Zeta := p.evalL0(p.proofChallenges.PlonkZeta, zetaPowN)

	vanishingZ1Terms := make([]QuadraticExtension, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]QuadraticExtension, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := p.qe.SubExtension(
			p.qe.MulExtension(l0Zeta, p.openings.PlonkZs[i]),
			l0Zeta,
		)
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

	return vanishingPartialProductsTerms
}

func (p *PlonkChip) Verify() {
	p.evalVanishingPoly()
}
