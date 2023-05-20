package common

import (
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/gates"
)

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap MerkleCap
	CircuitDigest     poseidon.Hash
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
	KIs                  []field.F
	NumPartialProducts   uint64
}

type FriConfig struct {
	RateBits        uint64
	CapHeight       uint64
	ProofOfWorkBits uint64
	NumQueryRounds  uint64
	// TODO: add FriReductionStrategy
}

func (fc *FriConfig) Rate() float64 {
	return 1.0 / float64((uint64(1) << fc.RateBits))
}

type FriParams struct {
	Config             FriConfig
	Hiding             bool
	DegreeBits         uint64
	ReductionArityBits []uint64
}
