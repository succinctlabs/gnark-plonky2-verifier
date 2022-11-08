package plonky2_verifier

import (
	"fmt"
	. "gnark-ed25519/field"
	"math/bits"
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
