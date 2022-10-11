package plonky2_verifier

import (
	. "gnark-ed25519/field"
	"gnark-ed25519/poseidon"

	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api          frontend.API
	field        frontend.API
	poseidonChip poseidon.PoseidonChip
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []F) Hash {
	return c.poseidonChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(proofWithPis ProofWithPublicInputs, publicInputsHash Hash, commonData CommonCircuitData) ProofChallenges {
	config := commonData.Config
	numChallenges := config.NumChallenges
	challenger := NewChallengerChip(c.api, c.field, c.poseidonChip)

	challenger.ObserveHash(commonData.CircuitDigest)
	challenger.ObserveHash(publicInputsHash)
	challenger.ObserveCap(proofWithPis.Proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

	_, _, _, _ = plonkAlphas, plonkBetas, plonkGammas, plonkZeta

	challenger.ObserveOpenings(proofWithPis.Proof.Openings.ToFriOpenings())

	return ProofChallenges{
		PlonkBetas:  plonkBetas,
		PlonkGammas: plonkGammas,
		PlonkAlphas: plonkAlphas,
		PlonkZeta:   plonkZeta,
		FriChallenges: challenger.GetFriChallenges(
			proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
			proofWithPis.Proof.OpeningProof.FinalPoly,
			proofWithPis.Proof.OpeningProof.PowWitness,
			commonData.DegreeBits, config.FriConfig,
		),
	}
}

func (c *VerifierChip) Verify(proofWithPis ProofWithPublicInputs, verifierData VerifierOnlyCircuitData, commonData CommonCircuitData) {
	publicInputsHash := c.GetPublicInputsHash(proofWithPis.PublicInputs)
	_ = c.GetChallenges(proofWithPis, publicInputsHash, commonData)
}
