package verifier

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/plonk"
)

type Proof struct {
	WiresCap                  common.MerkleCap
	PlonkZsPartialProductsCap common.MerkleCap
	QuotientPolysCap          common.MerkleCap
	Openings                  plonk.OpeningSet
	OpeningProof              common.FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []field.F
}

type ProofChallenges struct {
	PlonkBetas    []field.F
	PlonkGammas   []field.F
	PlonkAlphas   []field.F
	PlonkZeta     field.QuadraticExtension
	FriChallenges common.FriChallenges
}
