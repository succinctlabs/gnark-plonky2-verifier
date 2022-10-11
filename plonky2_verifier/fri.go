package plonky2_verifier

import (
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
