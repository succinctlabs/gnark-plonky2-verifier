package variables

import (
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type Proof struct {
	WiresCap                  FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	PlonkZsPartialProductsCap FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	QuotientPolysCap          FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	Openings                  OpeningSet
	OpeningProof              FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []gl.Variable // Length = CommonCircuitData.NumPublicInputs
}

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap FriMerkleCap
	CircuitDigest     poseidon.BN254HashOut
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
	Gates                []gates.Gate
	SelectorsInfo        gates.SelectorsInfo
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []gl.Variable
	NumPartialProducts   uint64
}
