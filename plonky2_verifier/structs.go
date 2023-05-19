package plonky2_verifier

import "gnark-plonky2-verifier/field"

type MerkleCap = []field.Hash

type MerkleProof struct {
	Siblings []field.Hash
}

type EvalProof struct {
	Elements    []field.F
	MerkleProof MerkleProof
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

type PolynomialCoeffs struct {
	Coeffs []field.QuadraticExtension
}

type FriProof struct {
	CommitPhaseMerkleCaps []MerkleCap
	QueryRoundProofs      []FriQueryRound
	FinalPoly             PolynomialCoeffs
	PowWitness            field.F
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

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap MerkleCap
	CircuitDigest     field.Hash
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
	Gates                []gate
	SelectorsInfo        SelectorsInfo
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []field.F
	NumPartialProducts   uint64
}

type ProofChallenges struct {
	PlonkBetas    []field.F
	PlonkGammas   []field.F
	PlonkAlphas   []field.F
	PlonkZeta     field.QuadraticExtension
	FriChallenges FriChallenges
}

type FriChallenges struct {
	FriAlpha        field.QuadraticExtension
	FriBetas        []field.QuadraticExtension
	FriPowResponse  field.F
	FriQueryIndices []field.F
}
