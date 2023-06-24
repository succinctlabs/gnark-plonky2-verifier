package common

import (
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type MerkleCap = []poseidon.PoseidonBN254HashOut

func NewMerkleCap(capHeight uint64) MerkleCap {
	return make([]poseidon.PoseidonBN254HashOut, 1<<capHeight)
}

type MerkleProof struct {
	Siblings []poseidon.PoseidonBN254HashOut // Length = CircuitConfig.FriConfig.DegreeBits + CircuitConfig.FriConfig.RateBits - CircuitConfig.FriConfig.CapHeight
}

func NewMerkleProof(merkleProofLen uint64) MerkleProof {
	return MerkleProof{Siblings: make([]poseidon.PoseidonBN254HashOut, merkleProofLen)}
}

type EvalProof struct {
	Elements    []gl.Variable // Length = [CommonCircuitData.Constants + CommonCircuitData.NumRoutedWires, CommonCircuitData.NumWires + CommonCircuitData.FriParams.Hiding ? 4 : 0, CommonCircuitData.NumChallenges * (1 + CommonCircuitData.NumPartialProducts) + salt, CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor + salt]
	MerkleProof MerkleProof
}

func NewEvalProof(elements []gl.Variable, merkleProof MerkleProof) EvalProof {
	return EvalProof{Elements: elements, MerkleProof: merkleProof}
}

type PolynomialCoeffs struct {
	Coeffs []gl.QuadraticExtensionVariable
}

func NewPolynomialCoeffs(numCoeffs uint64) PolynomialCoeffs {
	return PolynomialCoeffs{Coeffs: make([]gl.QuadraticExtensionVariable, numCoeffs)}
}

type OpeningSet struct {
	Constants       []gl.QuadraticExtensionVariable // Length = CommonCircuitData.Constants
	PlonkSigmas     []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumRoutedWires
	Wires           []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumWires
	PlonkZs         []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges
	PlonkZsNext     []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges
	PartialProducts []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges * CommonCircuitData.NumPartialProducts
	QuotientPolys   []gl.QuadraticExtensionVariable // Length = CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor
}

func NewOpeningSet(numConstants uint64, numRoutedWires uint64, numWires uint64, numChallenges uint64, numPartialProducts uint64, quotientDegreeFactor uint64) OpeningSet {
	return OpeningSet{
		Constants:       make([]gl.QuadraticExtensionVariable, numConstants),
		PlonkSigmas:     make([]gl.QuadraticExtensionVariable, numRoutedWires),
		Wires:           make([]gl.QuadraticExtensionVariable, numWires),
		PlonkZs:         make([]gl.QuadraticExtensionVariable, numChallenges),
		PlonkZsNext:     make([]gl.QuadraticExtensionVariable, numChallenges),
		PartialProducts: make([]gl.QuadraticExtensionVariable, numChallenges*numPartialProducts),
		QuotientPolys:   make([]gl.QuadraticExtensionVariable, numChallenges*quotientDegreeFactor),
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
	PublicInputs []gl.Variable // Length = CommonCircuitData.NumPublicInputs
}

type ProofChallenges struct {
	PlonkBetas    []gl.Variable
	PlonkGammas   []gl.Variable
	PlonkAlphas   []gl.Variable
	PlonkZeta     gl.QuadraticExtensionVariable
	FriChallenges FriChallenges
}

type FriInitialTreeProof struct {
	EvalsProofs []EvalProof // Length = 4
}

func NewFriInitialTreeProof(evalsProofs []EvalProof) FriInitialTreeProof {
	return FriInitialTreeProof{EvalsProofs: evalsProofs}
}

type FriQueryStep struct {
	Evals       []gl.QuadraticExtensionVariable // Length = [2^arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
	MerkleProof MerkleProof                     // Length = [regularSize - arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
}

func NewFriQueryStep(arityBit uint64, merkleProofLen uint64) FriQueryStep {
	return FriQueryStep{
		Evals:       make([]gl.QuadraticExtensionVariable, 1<<arityBit),
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
	PowWitness            gl.Variable
}

type FriChallenges struct {
	FriAlpha        gl.QuadraticExtensionVariable
	FriBetas        []gl.QuadraticExtensionVariable
	FriPowResponse  gl.Variable
	FriQueryIndices []gl.Variable
}
