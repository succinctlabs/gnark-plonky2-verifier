package plonk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/gates"
)

type PlonkChip struct {
	api   frontend.API                 `gnark:"-"`
	qeAPI *field.QuadraticExtensionAPI `gnark:"-"`

	commonData common.CommonCircuitData `gnark:"-"`

	DEGREE        field.F                  `gnark:"-"`
	DEGREE_BITS_F field.F                  `gnark:"-"`
	DEGREE_QE     field.QuadraticExtension `gnark:"-"`

	evaluateGatesChip *gates.EvaluateGatesChip
}

func NewPlonkChip(api frontend.API, qeAPI *field.QuadraticExtensionAPI, commonData common.CommonCircuitData) *PlonkChip {
	// TODO:  Should degreeBits be verified that it fits within the field and that degree is within uint64?

	evaluateGatesChip := gates.NewEvaluateGatesChip(
		api,
		qeAPI,
		commonData.Gates,
		commonData.NumGateConstraints,
		commonData.SelectorsInfo,
	)

	return &PlonkChip{
		api:   api,
		qeAPI: qeAPI,

		commonData: commonData,

		DEGREE:        *field.NewFieldConst(1 << commonData.DegreeBits),
		DEGREE_BITS_F: *field.NewFieldConst(commonData.DegreeBits),
		DEGREE_QE:     field.QuadraticExtension{*field.NewFieldConst(1 << commonData.DegreeBits), *field.ZERO_F},

		evaluateGatesChip: evaluateGatesChip,
	}
}

func (p *PlonkChip) expPowerOf2Extension(x field.QuadraticExtension) field.QuadraticExtension {
	for i := uint64(0); i < p.commonData.DegreeBits; i++ {
		x = p.qeAPI.SquareExtension(x)
	}

	return x
}

func (p *PlonkChip) evalL0(x field.QuadraticExtension, xPowN field.QuadraticExtension) field.QuadraticExtension {
	// L_0(x) = (x^n - 1) / (n * (x - 1))
	evalZeroPoly := p.qeAPI.SubExtension(
		xPowN,
		p.qeAPI.ONE_QE,
	)
	denominator := p.qeAPI.SubExtension(
		p.qeAPI.ScalarMulExtension(x, p.DEGREE),
		p.DEGREE_QE,
	)
	return p.qeAPI.DivExtension(
		evalZeroPoly,
		denominator,
	)
}

func (p *PlonkChip) checkPartialProducts(
	numerators []field.QuadraticExtension,
	denominators []field.QuadraticExtension,
	challengeNum uint64,
	openings common.OpeningSet,
) []field.QuadraticExtension {
	numPartProds := p.commonData.NumPartialProducts
	quotDegreeFactor := p.commonData.QuotientDegreeFactor

	productAccs := make([]field.QuadraticExtension, 0, numPartProds+2)
	productAccs = append(productAccs, openings.PlonkZs[challengeNum])
	productAccs = append(productAccs, openings.PartialProducts[challengeNum*numPartProds:(challengeNum+1)*numPartProds]...)
	productAccs = append(productAccs, openings.PlonkZsNext[challengeNum])

	partialProductChecks := make([]field.QuadraticExtension, 0, numPartProds)

	for i := uint64(0); i <= numPartProds; i += 1 {
		ppStartIdx := i * quotDegreeFactor
		numeProduct := numerators[ppStartIdx]
		denoProduct := denominators[ppStartIdx]
		for j := uint64(1); j < quotDegreeFactor; j++ {
			numeProduct = p.qeAPI.MulExtension(numeProduct, numerators[ppStartIdx+j])
			denoProduct = p.qeAPI.MulExtension(denoProduct, denominators[ppStartIdx+j])
		}

		partialProductCheck := p.qeAPI.SubExtension(
			p.qeAPI.MulExtension(productAccs[i], numeProduct),
			p.qeAPI.MulExtension(productAccs[i+1], denoProduct),
		)

		partialProductChecks = append(partialProductChecks, partialProductCheck)
	}
	return partialProductChecks
}

func (p *PlonkChip) evalVanishingPoly(vars gates.EvaluationVars, proofChallenges common.ProofChallenges, openings common.OpeningSet, zetaPowN field.QuadraticExtension) []field.QuadraticExtension {
	constraintTerms := p.evaluateGatesChip.EvaluateGateConstraints(vars)

	// Calculate the k[i] * x
	sIDs := make([]field.QuadraticExtension, p.commonData.Config.NumRoutedWires)

	for i := uint64(0); i < p.commonData.Config.NumRoutedWires; i++ {
		sIDs[i] = p.qeAPI.ScalarMulExtension(proofChallenges.PlonkZeta, p.commonData.KIs[i])
	}

	// Calculate L_0(zeta)
	l0Zeta := p.evalL0(proofChallenges.PlonkZeta, zetaPowN)

	vanishingZ1Terms := make([]field.QuadraticExtension, 0, p.commonData.Config.NumChallenges)
	vanishingPartialProductsTerms := make([]field.QuadraticExtension, 0, p.commonData.Config.NumChallenges*p.commonData.NumPartialProducts)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		// L_0(zeta) (Z(zeta) - 1) = 0
		z1_term := p.qeAPI.MulExtension(
			l0Zeta,
			p.qeAPI.SubExtension(openings.PlonkZs[i], p.qeAPI.ONE_QE))
		vanishingZ1Terms = append(vanishingZ1Terms, z1_term)

		numeratorValues := make([]field.QuadraticExtension, 0, p.commonData.Config.NumRoutedWires)
		denominatorValues := make([]field.QuadraticExtension, 0, p.commonData.Config.NumRoutedWires)
		for j := uint64(0); j < p.commonData.Config.NumRoutedWires; j++ {
			// The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
			// `beta * s_sigma + wire_value + gamma`.
			wireValuePlusGamma := p.qeAPI.AddExtension(
				openings.Wires[j],
				p.qeAPI.FieldToQE(proofChallenges.PlonkGammas[i]),
			)

			numerator := p.qeAPI.AddExtension(
				p.qeAPI.MulExtension(
					p.qeAPI.FieldToQE(proofChallenges.PlonkBetas[i]),
					sIDs[j],
				),
				wireValuePlusGamma,
			)

			denominator := p.qeAPI.AddExtension(
				p.qeAPI.MulExtension(
					p.qeAPI.FieldToQE(proofChallenges.PlonkBetas[i]),
					openings.PlonkSigmas[j],
				),
				wireValuePlusGamma,
			)

			numeratorValues = append(numeratorValues, numerator)
			denominatorValues = append(denominatorValues, denominator)
		}

		vanishingPartialProductsTerms = append(
			vanishingPartialProductsTerms,
			p.checkPartialProducts(numeratorValues, denominatorValues, i, openings)...,
		)
	}

	vanishingTerms := append(vanishingZ1Terms, vanishingPartialProductsTerms...)
	vanishingTerms = append(vanishingTerms, constraintTerms...)

	reducedValues := make([]field.QuadraticExtension, p.commonData.Config.NumChallenges)
	for i := uint64(0); i < p.commonData.Config.NumChallenges; i++ {
		reducedValues[i] = p.qeAPI.ZERO_QE
	}

	// reverse iterate the vanishingPartialProductsTerms array
	for i := len(vanishingTerms) - 1; i >= 0; i-- {
		for j := uint64(0); j < p.commonData.Config.NumChallenges; j++ {
			reducedValues[j] = p.qeAPI.AddExtension(
				vanishingTerms[i],
				p.qeAPI.ScalarMulExtension(
					reducedValues[j],
					proofChallenges.PlonkAlphas[j],
				),
			)
		}
	}

	return reducedValues
}

func (p *PlonkChip) Verify(proofChallenges common.ProofChallenges, openings common.OpeningSet, publicInputsHash poseidon.Hash) {
	// Calculate zeta^n
	zetaPowN := p.expPowerOf2Extension(proofChallenges.PlonkZeta)

	localConstants := openings.Constants
	localWires := openings.Wires
	vars := gates.NewEvaluationVars(
		localConstants,
		localWires,
		publicInputsHash,
	)

	vanishingPolysZeta := p.evalVanishingPoly(*vars, proofChallenges, openings, zetaPowN)

	// Calculate Z(H)
	zHZeta := p.qeAPI.SubExtension(zetaPowN, p.qeAPI.ONE_QE)

	// `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
	// Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
	// where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
	// So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
	// `quotient_degree_factor`-sized chunk of the original evaluations.
	for i := 0; i < len(vanishingPolysZeta); i++ {
		quotientPolysStartIdx := i * int(p.commonData.QuotientDegreeFactor)
		quotientPolysEndIdx := quotientPolysStartIdx + int(p.commonData.QuotientDegreeFactor)
		prod := p.qeAPI.MulExtension(
			zHZeta,
			p.qeAPI.ReduceWithPowers(
				openings.QuotientPolys[quotientPolysStartIdx:quotientPolysEndIdx],
				zetaPowN,
			),
		)

		p.qeAPI.AssertIsEqual(vanishingPolysZeta[i], prod)
	}
}
