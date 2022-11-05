package plonky2_verifier

import (
	. "gnark-ed25519/field"
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
