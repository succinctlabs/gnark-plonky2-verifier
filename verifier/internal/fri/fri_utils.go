package fri

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
)

type FriOpeningBatch struct {
	Values []field.QuadraticExtension
}

type FriOpenings struct {
	Batches []FriOpeningBatch
}

func ToFriOpenings(c common.OpeningSet) FriOpenings {
	values := c.Constants                         // num_constants + 1
	values = append(values, c.PlonkSigmas...)     // num_routed_wires
	values = append(values, c.Wires...)           // num_wires
	values = append(values, c.PlonkZs...)         // num_challenges
	values = append(values, c.PartialProducts...) // num_challenges * num_partial_products
	values = append(values, c.QuotientPolys...)   // num_challenges * quotient_degree_factor
	zetaBatch := FriOpeningBatch{Values: values}
	zetaNextBatch := FriOpeningBatch{Values: c.PlonkZsNext}
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
	Point       field.QuadraticExtension
	Polynomials []FriPolynomialInfo
}

type FriInstanceInfo struct {
	Oracles []FriOracleInfo
	Batches []FriBatchInfo
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

func polynomialInfoFromRange(c *common.CommonCircuitData, oracleIdx uint64, startPolyIdx uint64, endPolyIdx uint64) []FriPolynomialInfo {
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
func sigmasRange(c *common.CommonCircuitData) []uint64 {
	returnArr := make([]uint64, 0)
	for i := c.NumConstants; i <= c.NumConstants+c.Config.NumRoutedWires; i++ {
		returnArr = append(returnArr, i)
	}

	return returnArr
}

func numPreprocessedPolys(c *common.CommonCircuitData) uint64 {
	sigmasRange := sigmasRange(c)
	return sigmasRange[len(sigmasRange)-1]
}

func numZSPartialProductsPolys(c *common.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * (1 + c.NumPartialProducts)
}

func numQuotientPolys(c *common.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * c.QuotientDegreeFactor
}

func friPreprocessedPolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	return polynomialInfoFromRange(
		c,
		CONSTANTS_SIGMAS.index,
		0,
		numPreprocessedPolys(c),
	)
}

func friWirePolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	numWirePolys := c.Config.NumWires
	return polynomialInfoFromRange(c, WIRES.index, 0, numWirePolys)
}

func friZSPartialProductsPolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		numZSPartialProductsPolys(c),
	)
}

func friQuotientPolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	return polynomialInfoFromRange(
		c,
		QUOTIENT.index,
		0,
		numQuotientPolys(c),
	)
}

func friZSPolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	return polynomialInfoFromRange(
		c,
		ZS_PARTIAL_PRODUCTS.index,
		0,
		c.Config.NumChallenges,
	)
}

func friOracles(c *common.CommonCircuitData) []FriOracleInfo {
	return []FriOracleInfo{
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

func friAllPolys(c *common.CommonCircuitData) []FriPolynomialInfo {
	returnArr := make([]FriPolynomialInfo, 0)
	returnArr = append(returnArr, friPreprocessedPolys(c)...)
	returnArr = append(returnArr, friWirePolys(c)...)
	returnArr = append(returnArr, friZSPartialProductsPolys(c)...)
	returnArr = append(returnArr, friQuotientPolys(c)...)

	return returnArr
}

func GetFriInstance(c *common.CommonCircuitData, qeAPI *field.QuadraticExtensionAPI, zeta field.QuadraticExtension, degreeBits uint64) FriInstanceInfo {
	zetaBatch := FriBatchInfo{
		Point:       zeta,
		Polynomials: friAllPolys(c),
	}

	g := field.GoldilocksPrimitiveRootOfUnity(degreeBits)
	zetaNext := qeAPI.MulExtension(qeAPI.FieldToQE(field.NewFieldConst(g.Uint64())), zeta)

	zetaNextBath := FriBatchInfo{
		Point:       zetaNext,
		Polynomials: friZSPolys(c),
	}

	return FriInstanceInfo{
		Oracles: friOracles(c),
		Batches: []FriBatchInfo{zetaBatch, zetaNextBath},
	}
}
