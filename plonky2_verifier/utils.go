package plonky2_verifier

import (
	"fmt"
	. "gnark-ed25519/field"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

func reduceWithPowers(qe *QuadraticExtensionAPI, terms []QuadraticExtension, scalar QuadraticExtension) QuadraticExtension {
	sum := qe.ZERO_QE

	for i := len(terms) - 1; i >= 0; i-- {
		sum = qe.AddExtension(
			qe.MulExtension(
				sum,
				scalar,
			),
			terms[i],
		)
	}

	return sum
}

// Computes `log_2(n)`, panicking if `n` is not a power of two.
func log2Strict(n uint) int {
	res := bits.TrailingZeros(n)
	if n>>res != 1 {
		panic(fmt.Sprintf("Not a power of two: %d", n))
	}
	return res
}

func SelectHash(fieldAPI frontend.API, bit frontend.Variable, leftHash, rightHash Hash) Hash {
	var returnHash Hash
	for i := 0; i < 4; i++ {
		returnHash[i] = fieldAPI.Select(bit, leftHash[i], rightHash[i]).(F)
	}

	return returnHash
}

func Lookup2Hash(fieldAPI frontend.API, b0 frontend.Variable, b1 frontend.Variable, h0, h1, h2, h3 Hash) Hash {
	var returnHash Hash

	for i := 0; i < 4; i++ {
		returnHash[i] = fieldAPI.Lookup2(b0, b1, h0[i], h1[i], h2[i], h3[i]).(F)
	}

	return returnHash
}

func AssertIsEqualHash(fieldAPI frontend.API, h1, h2 Hash) {
	for i := 0; i < 4; i++ {
		fieldAPI.AssertIsEqual(h1[0], h2[0])
	}
}
