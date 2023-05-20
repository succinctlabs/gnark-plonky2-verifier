package common

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type MerkleCap = []poseidon.Hash

type MerkleProof struct {
	Siblings []poseidon.Hash
}

type EvalProof struct {
	Elements    []field.F
	MerkleProof MerkleProof
}

type PolynomialCoeffs struct {
	Coeffs []field.QuadraticExtension
}

type OpeningSet struct {
	Constants       []field.QuadraticExtension
	PlonkSigmas     []field.QuadraticExtension
	Wires           []field.QuadraticExtension
	PlonkZs         []field.QuadraticExtension
	PlonkZsNext     []field.QuadraticExtension
	PartialProducts []field.QuadraticExtension
	QuotientPolys   []field.QuadraticExtension
}

type Proof struct {
	WiresCap                  MerkleCap
	PlonkZsPartialProductsCap MerkleCap
	QuotientPolysCap          MerkleCap
	Openings                  OpeningSet
	OpeningProof              FriProof
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
	FriChallenges FriChallenges
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof
}

type FriQueryStep struct {
	Evals       []field.QuadraticExtension
	MerkleProof MerkleProof
}

type FriQueryRound struct {
	InitialTreesProof FriInitialTreeProof
	Steps             []FriQueryStep
}

type FriProof struct {
	CommitPhaseMerkleCaps []MerkleCap
	QueryRoundProofs      []FriQueryRound
	FinalPoly             PolynomialCoeffs
	PowWitness            field.F
}

type FriChallenges struct {
	FriAlpha        field.QuadraticExtension
	FriBetas        []field.QuadraticExtension
	FriPowResponse  field.F
	FriQueryIndices []field.F
}
