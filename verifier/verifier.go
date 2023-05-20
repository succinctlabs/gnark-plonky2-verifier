package verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/plonk"
)

type VerifierChip struct {
	api          frontend.API                 `gnark:"-"`
	fieldAPI     frontend.API                 `gnark:"-"`
	qeAPI        *field.QuadraticExtensionAPI `gnark:"-"`
	poseidonChip *poseidon.PoseidonChip
	plonkChip    *plonk.PlonkChip
	friChip      *fri.FriChip
}

func NewVerifierChip(api frontend.API, commonCircuitData common.CommonCircuitData) *VerifierChip {

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(fieldAPI, commonCircuitData.DegreeBits)
	hashAPI := poseidon.NewHashAPI(fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)

	friChip := fri.NewFriChip(api, fieldAPI, qeAPI, hashAPI, poseidonChip, &commonCircuitData.FriParams)
	plonkChip := plonk.NewPlonkChip(api, qeAPI, commonCircuitData)

	return &VerifierChip{
		api:          api,
		fieldAPI:     fieldAPI,
		qeAPI:        qeAPI,
		poseidonChip: poseidonChip,
		plonkChip:    plonkChip,
		friChip:      friChip,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []field.F) poseidon.Hash {
	return c.poseidonChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proofWithPis common.ProofWithPublicInputs,
	publicInputsHash poseidon.Hash,
	commonData common.CommonCircuitData,
	verifierData common.VerifierOnlyCircuitData,
) common.ProofChallenges {
	config := commonData.Config
	numChallenges := config.NumChallenges
	challenger := plonk.NewChallengerChip(c.api, c.fieldAPI, c.poseidonChip)

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

	challenger.ObserveOpenings(fri.ToFriOpenings(proofWithPis.Proof.Openings))

	return common.ProofChallenges{
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

func (c *VerifierChip) Verify(proofWithPis common.ProofWithPublicInputs, verifierData common.VerifierOnlyCircuitData, commonData common.CommonCircuitData) {
	// TODO: Verify shape of the proof?

	publicInputsHash := c.GetPublicInputsHash(proofWithPis.PublicInputs)
	proofChallenges := c.GetChallenges(proofWithPis, publicInputsHash, commonData, verifierData)

	c.plonkChip.Verify(proofChallenges, proofWithPis.Proof.Openings, publicInputsHash)

	initialMerkleCaps := []common.MerkleCap{
		verifierData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	// Seems like there is a bug in the emulated field code.
	// Add ZERO to all of the fri challenges values to reduce them.
	proofChallenges.PlonkZeta[0] = c.fieldAPI.Add(proofChallenges.PlonkZeta[0], field.ZERO_F).(field.F)
	proofChallenges.PlonkZeta[1] = c.fieldAPI.Add(proofChallenges.PlonkZeta[1], field.ZERO_F).(field.F)

	proofChallenges.FriChallenges.FriAlpha[0] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriAlpha[0], field.ZERO_F).(field.F)
	proofChallenges.FriChallenges.FriAlpha[1] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriAlpha[1], field.ZERO_F).(field.F)

	for i := 0; i < len(proofChallenges.FriChallenges.FriBetas); i++ {
		proofChallenges.FriChallenges.FriBetas[i][0] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriBetas[i][0], field.ZERO_F).(field.F)
		proofChallenges.FriChallenges.FriBetas[i][1] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriBetas[i][1], field.ZERO_F).(field.F)
	}

	proofChallenges.FriChallenges.FriPowResponse = c.fieldAPI.Add(proofChallenges.FriChallenges.FriPowResponse, field.ZERO_F).(field.F)

	for i := 0; i < len(proofChallenges.FriChallenges.FriQueryIndices); i++ {
		proofChallenges.FriChallenges.FriQueryIndices[i] = c.fieldAPI.Add(proofChallenges.FriChallenges.FriQueryIndices[i], field.ZERO_F).(field.F)
	}

	c.friChip.VerifyFriProof(
		fri.GetFriInstance(&commonData, c.qeAPI, proofChallenges.PlonkZeta, commonData.DegreeBits),
		fri.ToFriOpenings(proofWithPis.Proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)
}
