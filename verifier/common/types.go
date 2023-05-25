package common

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type MerkleCap = []poseidon.Hash

func NewMerkleCap(capHeight uint64) MerkleCap {
	return make([]poseidon.Hash, 1<<capHeight)
}

type MerkleProof struct {
	Siblings []poseidon.Hash // Length = CircuitConfig.FriConfig.DegreeBits + CircuitConfig.FriConfig.RateBits - CircuitConfig.FriConfig.CapHeight
}

func NewMerkleProof(merkleProofLen uint64) MerkleProof {
	return MerkleProof{Siblings: make([]poseidon.Hash, merkleProofLen)}
}

type EvalProof struct {
	Elements    []field.F // Length = [CommonCircuitData.Constants + CommonCircuitData.NumRoutedWires, CommonCircuitData.NumWires + CommonCircuitData.FriParams.Hiding ? 4 : 0, CommonCircuitData.NumChallenges * (1 + CommonCircuitData.NumPartialProducts) + salt, CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor + salt]
	MerkleProof MerkleProof
}

func NewEvalProof(elements []field.F, merkleProof MerkleProof) EvalProof {
	return EvalProof{Elements: elements, MerkleProof: merkleProof}
}

type PolynomialCoeffs struct {
	Coeffs []field.QuadraticExtension
}

func NewPolynomialCoeffs(numCoeffs uint64) PolynomialCoeffs {
	return PolynomialCoeffs{Coeffs: make([]field.QuadraticExtension, numCoeffs)}
}

type OpeningSet struct {
	Constants       []field.QuadraticExtension // Length = CommonCircuitData.Constants
	PlonkSigmas     []field.QuadraticExtension // Length = CommonCircuitData.NumRoutedWires
	Wires           []field.QuadraticExtension // Length = CommonCircuitData.NumWires
	PlonkZs         []field.QuadraticExtension // Length = CommonCircuitData.NumChallenges
	PlonkZsNext     []field.QuadraticExtension // Length = CommonCircuitData.NumChallenges
	PartialProducts []field.QuadraticExtension // Length = CommonCircuitData.NumChallenges * CommonCircuitData.NumPartialProducts
	QuotientPolys   []field.QuadraticExtension // Length = CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor
}

func NewOpeningSet(numConstants uint64, numRoutedWires uint64, numWires uint64, numChallenges uint64, numPartialProducts uint64, quotientDegreeFactor uint64) OpeningSet {
	return OpeningSet{
		Constants:       make([]field.QuadraticExtension, numConstants),
		PlonkSigmas:     make([]field.QuadraticExtension, numRoutedWires),
		Wires:           make([]field.QuadraticExtension, numWires),
		PlonkZs:         make([]field.QuadraticExtension, numChallenges),
		PlonkZsNext:     make([]field.QuadraticExtension, numChallenges),
		PartialProducts: make([]field.QuadraticExtension, numChallenges*numPartialProducts),
		QuotientPolys:   make([]field.QuadraticExtension, numChallenges*quotientDegreeFactor),
	}
}

type Proof struct {
	WiresCap                  MerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	PlonkZsPartialProductsCap MerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	QuotientPolysCap          MerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	Openings                  OpeningSet
	OpeningProof              FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []field.F // Length = CommonCircuitData.NumPublicInputs
}

type ProofChallenges struct {
	PlonkBetas    []field.F
	PlonkGammas   []field.F
	PlonkAlphas   []field.F
	PlonkZeta     field.QuadraticExtension
	FriChallenges FriChallenges
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof // Length = 4
}

func NewFriInitialTreeProof(evalsProofs []EvalProof) FriInitialTreeProof {
	return FriInitialTreeProof{EvalsProofs: evalsProofs}
}

type FriQueryStep struct {
	Evals       []field.QuadraticExtension // Length = [2^arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
	MerkleProof MerkleProof                // Length = [regularSize - arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
}

func NewFriQueryStep(arityBit uint64, merkleProofLen uint64) FriQueryStep {
	return FriQueryStep{
		Evals:       make([]field.QuadraticExtension, 1<<arityBit),
		MerkleProof: NewMerkleProof(merkleProofLen),
	}
}

type FriQueryRound struct {
	InitialTreesProof FriInitialTreeProof
	Steps             []FriQueryStep // Length = Len(CommonCircuitData.FriParams.ReductionArityBits)
}

func NewFriQueryRound(steps []FriQueryStep, initialTreesProof FriInitialTreeProof) FriQueryRound {
	return FriQueryRound{InitialTreesProof: initialTreesProof, Steps: steps}
}

type FriProof struct {
	CommitPhaseMerkleCaps []MerkleCap     // Length = Len(CommonCircuitData.FriParams.ReductionArityBits)
	QueryRoundProofs      []FriQueryRound // Length = CommonCircuitData.FriConfig.FriParams.NumQueryRounds
	FinalPoly             PolynomialCoeffs
	PowWitness            field.F
}

type FriChallenges struct {
	FriAlpha        field.QuadraticExtension
	FriBetas        []field.QuadraticExtension
	FriPowResponse  field.F
	FriQueryIndices []field.F
}
