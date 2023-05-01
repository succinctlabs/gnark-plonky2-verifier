package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
	"gnark-plonky2-verifier/poseidon"

	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api          frontend.API           `gnark:"-"`
	fieldAPI     frontend.API           `gnark:"-"`
	qeAPI        *QuadraticExtensionAPI `gnark:"-"`
	poseidonChip *poseidon.PoseidonChip
	plonkChip    *PlonkChip
	friChip      *FriChip
}

func NewVerifierChip(api frontend.API, fieldAPI frontend.API, qeAPI *QuadraticExtensionAPI, poseidonChip *poseidon.PoseidonChip, plonkChip *PlonkChip, friChip *FriChip) *VerifierChip {
	return &VerifierChip{
		api:          api,
		fieldAPI:     fieldAPI,
		qeAPI:        qeAPI,
		poseidonChip: poseidonChip,
		plonkChip:    plonkChip,
		friChip:      friChip,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []F) Hash {
	return c.poseidonChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(proofWithPis ProofWithPublicInputs, publicInputsHash Hash, commonData CommonCircuitData, verifierData VerifierOnlyCircuitData) ProofChallenges {
	config := commonData.Config
	numChallenges := config.NumChallenges
	challenger := NewChallengerChip(c.api, c.fieldAPI, c.poseidonChip)

	var circuitDigest = verifierData.CircuitDigest

	challenger.ObserveHash(circuitDigest)
	challenger.ObserveHash(publicInputsHash)
	challenger.ObserveCap(proofWithPis.Proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

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
			commonData.DegreeBits,
			config.FriConfig,
		),
	}
}

func (c *VerifierChip) Verify(proofWithPis ProofWithPublicInputs, verifierData VerifierOnlyCircuitData, commonData CommonCircuitData) {
	// TODO: Verify shape of the proof?

	publicInputsHash := c.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := c.GetChallenges(proofWithPis, publicInputsHash, commonData, verifierData)

	c.plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)

	initialMerkleCaps := []MerkleCap{
		verifierData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	// Seems like there is a bug in the emulated field code.
	// Add ZERO to all of the fri challenges values to reduce them.
	proofChallenges.PlonkZeta[0] = c.fieldAPI.Add(proofChallenges.PlonkZeta[0], ZERO_F).(F)
	proofChallenges.PlonkZeta[1] = c.fieldAPI.Add(proofChallenges.PlonkZeta[1], ZERO_F).(F)

	proofChallenges.FriChallenges.FriAlpha[0] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriAlpha[0], ZERO_F).(F)
	proofChallenges.FriChallenges.FriAlpha[1] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriAlpha[1], ZERO_F).(F)

	for i := 0; i < len(proofChallenges.FriChallenges.FriBetas); i++ {
		proofChallenges.FriChallenges.FriBetas[i][0] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriBetas[i][0], ZERO_F).(F)
		proofChallenges.FriChallenges.FriBetas[i][1] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriBetas[i][1], ZERO_F).(F)
	}

	proofChallenges.FriChallenges.FriPowResponse = c.fieldAPI.Add(proofChallenges.FriChallenges.FriPowResponse, ZERO_F).(F)

	for i := 0; i < len(proofChallenges.FriChallenges.FriQueryIndices); i++ {
		proofChallenges.FriChallenges.FriQueryIndices[i] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriQueryIndices[i], ZERO_F).(F)
	}

	c.friChip.VerifyFriProof(
		commonData.GetFriInstance(c.qeAPI, proofChallenges.PlonkZeta, commonData.DegreeBits),
		proofWithPis.Proof.Openings.ToFriOpenings(),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)
}
