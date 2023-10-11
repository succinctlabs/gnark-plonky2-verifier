package fri

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

type PolynomialInfo struct {
	OracleIndex    uint64
	PolynomialInfo uint64
}

type OracleInfo struct {
	NumPolys uint64
	Blinding bool
}

type PlonkOracle struct {
	index    uint64
	blinding bool
}

var CONSTANTS_SIGMAS = PlonkOracle{
	index:    0,
	blinding: false,
}

var WIRES = PlonkOracle{
	index:    1,
	blinding: true,
}

var ZS_PARTIAL_PRODUCTS = PlonkOracle{
	index:    2,
	blinding: true,
}

var QUOTIENT = PlonkOracle{
	index:    3,
	blinding: true,
}

func polynomialInfoFromRange(c *types.CommonCircuitData, oracleIdx uint64, startPolyIdx uint64, endPolyIdx uint64) []PolynomialInfo {
	returnArr := make([]PolynomialInfo, 0)
	for i := startPolyIdx; i < endPolyIdx; i++ {
		returnArr = append(returnArr,
			PolynomialInfo{
				OracleIndex:    oracleIdx,
				PolynomialInfo: i,
			})
	}

	return returnArr
}

// Range of the sigma polynomials in the `constants_sigmas_commitment`.
func sigmasRange(c *types.CommonCircuitData) []uint64 {
	returnArr := make([]uint64, 0)
	for i := c.NumConstants; i <= c.NumConstants+c.Config.NumRoutedWires; i++ {
		returnArr = append(returnArr, i)
	}

	return returnArr
}

func numPreprocessedPolys(c *types.CommonCircuitData) uint64 {
	sigmasRange := sigmasRange(c)
	return sigmasRange[len(sigmasRange)-1]
}

func numZSPartialProductsPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * (1 + c.NumPartialProducts)
}

func numQuotientPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * c.QuotientDegreeFactor
}

func friPreprocessedPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		CONSTANTS_SIGMAS.index,
		0,
		numPreprocessedPolys(c),
	)
}

func friWirePolys(c *types.CommonCircuitData) []PolynomialInfo {
	numWirePolys := c.Config.NumWires
	return polynomialInfoFromRange(c, WIRES.index, 0, numWirePolys)
}

func friZSPartialProductsPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		numZSPartialProductsPolys(c),
	)
}

func friQuotientPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		QUOTIENT.index,
		0,
		numQuotientPolys(c),
	)
}

func friZSPolys(c *types.CommonCircuitData) []PolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		c.Config.NumChallenges,
	)
}

func friOracles(c *types.CommonCircuitData) []OracleInfo {
	return []OracleInfo{
		{
			NumPolys: numPreprocessedPolys(c),
			Blinding: CONSTANTS_SIGMAS.blinding,
		},
		{
			NumPolys: c.Config.NumWires,
			Blinding: WIRES.blinding,
		},
		{
			NumPolys: numZSPartialProductsPolys(c),
			Blinding: ZS_PARTIAL_PRODUCTS.blinding,
		},
		{
			NumPolys: numQuotientPolys(c),
			Blinding: QUOTIENT.blinding,
		},
	}
}

func friAllPolys(c *types.CommonCircuitData) []PolynomialInfo {
	returnArr := make([]PolynomialInfo, 0)
	returnArr = append(returnArr, friPreprocessedPolys(c)...)
	returnArr = append(returnArr, friWirePolys(c)...)
	returnArr = append(returnArr, friZSPartialProductsPolys(c)...)
	returnArr = append(returnArr, friQuotientPolys(c)...)

	return returnArr
}
