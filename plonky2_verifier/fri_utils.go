package plonky2_verifier

import (
	"gnark-ed25519/field"
	. "gnark-ed25519/field"
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

type FriPolynomialInfo struct {
	OracleIndex    uint64
	PolynomialInfo uint64
}

type FriOracleInfo struct {
	NumPolys uint64
	Blinding bool
}

type FriBatchInfo struct {
	Point       QuadraticExtension
	Polynomials []FriPolynomialInfo
}

type FriInstanceInfo struct {
	Oracles []FriOracleInfo
	Batches []FriBatchInfo
}

func (c *CommonCircuitData) polynomialInfoFromRange(oracleIdx uint64, startPolyIdx uint64, endPolyIdx uint64) []FriPolynomialInfo {
	returnArr := make([]FriPolynomialInfo, 0)
	for i := startPolyIdx; i < endPolyIdx; i++ {
		returnArr = append(returnArr,
			FriPolynomialInfo{
				OracleIndex:    oracleIdx,
				PolynomialInfo: i,
			})
	}

	return returnArr

}

// Range of the sigma polynomials in the `constants_sigmas_commitment`.
func (c *CommonCircuitData) sigmasRange() []uint64 {
	returnArr := make([]uint64, 0)
	for i := c.NumConstants; i <= c.NumConstants+c.Config.NumRoutedWires; i++ {
		returnArr = append(returnArr, i)
	}

	return returnArr
}

func (c *CommonCircuitData) numPreprocessedPolys() uint64 {
	sigmasRange := c.sigmasRange()
	return sigmasRange[len(sigmasRange)-1]
}

func (c *CommonCircuitData) numZSPartialProductsPolys() uint64 {
	return c.Config.NumChallenges * (1 + c.NumPartialProducts)
}

func (c *CommonCircuitData) numQuotientPolys() uint64 {
	return c.Config.NumChallenges * c.QuotientDegreeFactor
}

func (c *CommonCircuitData) friPreprocessedPolys() []FriPolynomialInfo {
	return c.polynomialInfoFromRange(
		CONSTANTS_SIGMAS.index,
		0,
		c.numPreprocessedPolys(),
	)
}

func (c *CommonCircuitData) friWirePolys() []FriPolynomialInfo {
	numWirePolys := c.Config.NumWires
	return c.polynomialInfoFromRange(WIRES.index, 0, numWirePolys)
}

func (c *CommonCircuitData) friZSPartialProductsPolys() []FriPolynomialInfo {
	return c.polynomialInfoFromRange(
		ZS_PARTIAL_PRODUCTS.index,
		0,
		c.numZSPartialProductsPolys(),
	)
}

func (c *CommonCircuitData) friQuotientPolys() []FriPolynomialInfo {
	return c.polynomialInfoFromRange(
		QUOTIENT.index,
		0,
		c.numQuotientPolys(),
	)
}

func (c *CommonCircuitData) friZSPolys() []FriPolynomialInfo {
	return c.polynomialInfoFromRange(
		ZS_PARTIAL_PRODUCTS.index,
		0,
		c.Config.NumChallenges,
	)
}

func (c *CommonCircuitData) friOracles() []FriOracleInfo {
	return []FriOracleInfo{
		{
			NumPolys: c.numPreprocessedPolys(),
			Blinding: CONSTANTS_SIGMAS.blinding,
		},
		{
			NumPolys: c.Config.NumWires,
			Blinding: WIRES.blinding,
		},
		{
			NumPolys: c.numZSPartialProductsPolys(),
			Blinding: ZS_PARTIAL_PRODUCTS.blinding,
		},
		{
			NumPolys: c.numQuotientPolys(),
			Blinding: QUOTIENT.blinding,
		},
	}
}

func (c *CommonCircuitData) friAllPolys() []FriPolynomialInfo {
	returnArr := make([]FriPolynomialInfo, 0)
	returnArr = append(returnArr, c.friPreprocessedPolys()...)
	returnArr = append(returnArr, c.friWirePolys()...)
	returnArr = append(returnArr, c.friZSPartialProductsPolys()...)
	returnArr = append(returnArr, c.friQuotientPolys()...)

	return returnArr
}

func (c *CommonCircuitData) GetFriInstance(qeAPI *QuadraticExtensionAPI, zeta QuadraticExtension, degreeBits uint64) FriInstanceInfo {
	zetaBatch := FriBatchInfo{
		Point:       zeta,
		Polynomials: c.friAllPolys(),
	}

	g := field.GoldilocksPrimitiveRootOfUnity(degreeBits)
	zetaNext := qeAPI.MulExtension(QuadraticExtension{field.NewFieldElement(g.Uint64()), field.ZERO_F}, zeta)

	zetaNextBath := FriBatchInfo{
		Point:       zetaNext,
		Polynomials: c.friZSPolys(),
	}

	return FriInstanceInfo{
		Oracles: c.friOracles(),
		Batches: []FriBatchInfo{zetaBatch, zetaNextBath},
	}
}
