package types

import "github.com/succinctlabs/gnark-plonky2-verifier/plonk/gates"

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
	Config CircuitConfig
	FriParams
	GateIds              []string
	SelectorsInfo        gates.SelectorsInfo
	DegreeBits           uint64
	QuotientDegreeFactor uint64
	NumGateConstraints   uint64
	NumConstants         uint64
	NumPublicInputs      uint64
	KIs                  []uint64
	NumPartialProducts   uint64
}
