package plonky2_verifier

import (
	. "gnark-ed25519/field"
)

type MerkleCap = []Hash

type MerkleProof struct {
	Siblings []Hash
}

type EvalProof struct {
	Elements    []F
	MerkleProof MerkleProof
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof
}

type FriQueryStep struct {
	Evals       []QuadraticExtension
	MerkleProof MerkleProof
}

type FriQueryRound struct {
	InitialTreesProof FriInitialTreeProof
	Steps             []FriQueryStep
}

type PolynomialCoeffs struct {
	Coeffs []QuadraticExtension
}

type FriProof struct {
	CommitPhaseMerkleCaps []MerkleCap
	QueryRoundProofs      []FriQueryRound
	FinalPoly             PolynomialCoeffs
	PowWitness            F
}

type OpeningSet struct {
	Constants       []QuadraticExtension
	PlonkSigmas     []QuadraticExtension
	Wires           []QuadraticExtension
	PlonkZs         []QuadraticExtension
	PlonkZsNext     []QuadraticExtension
	PartialProducts []QuadraticExtension
	QuotientPolys   []QuadraticExtension
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
	PublicInputs []F
}

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap MerkleCap
}

type FriConfig struct {
	RateBits        uint64
	CapHeight       uint64
	ProofOfWorkBits uint64
	NumQueryRounds  uint64
	// TODO: add FriReductionStrategy
}

func (fc *FriConfig) rate() float64 {
	return 1.0 / float64((uint64(1) << fc.RateBits))
}

type FriParams struct {
	Config             FriConfig
	Hiding             bool
	DegreeBits         uint64
	ReductionArityBits []uint64
}

type CircuitConfig struct {
	NumWires                uint64
	NumRoutedWires          uint64
	NumConstants            uint64
	UseBaseArithmeticGate   bool
	SecurityBits            uint64
	NumChallenges           uint64
	ZeroKnowledge           bool
	MaxQuotientDegreeFactor uint64
	FriConfig               FriConfig
}

type CommonCircuitData struct {
	Config               CircuitConfig
	FriParams            FriParams
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []F
	NumPartialProducts   uint64
	CircuitDigest        Hash
}

type ProofChallenges struct {
	PlonkBetas    []F
	PlonkGammas   []F
	PlonkAlphas   []F
	PlonkZeta     QuadraticExtension
	FriChallenges FriChallenges
}

type FriChallenges struct {
	FriAlpha         QuadraticExtension
	FriBetas         []QuadraticExtension
	FriPowResponse   F
	FriQueryIndicies []F
}
