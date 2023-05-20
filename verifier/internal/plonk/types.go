package plonk

import "github.com/succinctlabs/gnark-plonky2-verifier/field"

type OpeningSet struct {
	Constants       []field.QuadraticExtension
	PlonkSigmas     []field.QuadraticExtension
	Wires           []field.QuadraticExtension
	PlonkZs         []field.QuadraticExtension
	PlonkZsNext     []field.QuadraticExtension
	PartialProducts []field.QuadraticExtension
	QuotientPolys   []field.QuadraticExtension
}
