package variables

import gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"

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

type ProofChallenges struct {
	PlonkBetas    []gl.Variable
	PlonkGammas   []gl.Variable
	PlonkAlphas   []gl.Variable
	PlonkZeta     gl.QuadraticExtensionVariable
	FriChallenges FriChallenges
}
