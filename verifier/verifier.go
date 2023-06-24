package verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/challenger"
	"github.com/succinctlabs/gnark-plonky2-verifier/fri"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/plonk"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
)

type VerifierChip struct {
	api               frontend.API `gnark:"-"`
	poseidonChip      *poseidon.PoseidonChip
	poseidonBN254Chip *poseidon.PoseidonBN254Chip
	plonkChip         *plonk.PlonkChip
	friChip           *fri.FriChip
}

func NewVerifierChip(api frontend.API, commonCircuitData common.CommonCircuitData) *VerifierChip {
	poseidonBN254Chip := poseidon.NewPoseidonBN254Chip(api)

	friChip := fri.NewFriChip(api, poseidonBN254Chip, &commonCircuitData.FriParams)
	plonkChip := plonk.NewPlonkChip(api, commonCircuitData)

	// We are using goldilocks poseidon for the challenge computation
	poseidonChip := poseidon.NewPoseidonChip(api)

	return &VerifierChip{
		api:               api,
		poseidonChip:      poseidonChip,
		poseidonBN254Chip: poseidonBN254Chip,
		plonkChip:         plonkChip,
		friChip:           friChip,
	}
}

func (c *VerifierChip) GetPublicInputsHash(publicInputs []gl.Variable) poseidon.PoseidonHashOut {
	return c.poseidonChip.HashNoPad(publicInputs)
}

func (c *VerifierChip) GetChallenges(
	proof common.Proof,
	publicInputsHash poseidon.PoseidonHashOut,
	commonData common.CommonCircuitData,
	verifierData common.VerifierOnlyCircuitData,
) common.ProofChallenges {
	config := commonData.Config
	numChallenges := config.NumChallenges
	challenger := challenger.NewChallengerChip(c.api, c.poseidonChip, c.poseidonBN254Chip)

	var circuitDigest = verifierData.CircuitDigest

	challenger.ObserveBN254Hash(circuitDigest)
	challenger.ObserveHash(publicInputsHash)
	challenger.ObserveCap(proof.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(proof.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

	challenger.ObserveOpenings(fri.ToFriOpenings(proof.Openings))

	return common.ProofChallenges{
		PlonkBetas:  plonkBetas,
		PlonkGammas: plonkGammas,
		PlonkAlphas: plonkAlphas,
		PlonkZeta:   plonkZeta,
		FriChallenges: challenger.GetFriChallenges(
			proof.OpeningProof.CommitPhaseMerkleCaps,
			proof.OpeningProof.FinalPoly,
			proof.OpeningProof.PowWitness,
			commonData.DegreeBits,
			config.FriConfig,
		),
	}
}

/*
func (c *VerifierChip) generateProofInput(commonData common.CommonCircuitData) common.ProofWithPublicInputs {
	// Generate the parts of the witness that is for the plonky2 proof input

	capHeight := commonData.Config.FriConfig.CapHeight

	friCommitPhaseMerkleCaps := []common.MerkleCap{}
	for i := 0; i < len(commonData.FriParams.ReductionArityBits); i++ {
		friCommitPhaseMerkleCaps = append(friCommitPhaseMerkleCaps, common.NewMerkleCap(capHeight))
	}

	salt := commonData.SaltSize()
	numLeavesPerOracle := []uint{
		commonData.NumPreprocessedPolys(),
		commonData.Config.NumWires + salt,
		commonData.NumZsPartialProductsPolys() + salt,
		commonData.NumQuotientPolys() + salt,
	}
	friQueryRoundProofs := []common.FriQueryRound{}
	for i := uint64(0); i < commonData.FriParams.Config.NumQueryRounds; i++ {
		evalProofs := []common.EvalProof{}
		merkleProofLen := commonData.FriParams.LDEBits() - capHeight
		for _, numLeaves := range numLeavesPerOracle {
			leaves := make([]field.F, numLeaves)
			merkleProof := common.NewMerkleProof(merkleProofLen)
			evalProofs = append(evalProofs, common.NewEvalProof(leaves, merkleProof))
		}

		initialTreesProof := common.NewFriInitialTreeProof(evalProofs)
		steps := []common.FriQueryStep{}
		for _, arityBit := range commonData.FriParams.ReductionArityBits {
			if merkleProofLen < arityBit {
				panic("merkleProofLen < arityBits")
			}

			steps = append(steps, common.NewFriQueryStep(arityBit, merkleProofLen))
		}

		friQueryRoundProofs = append(friQueryRoundProofs, common.NewFriQueryRound(steps, initialTreesProof))
	}

	proofInput := common.ProofWithPublicInputs{
		Proof: common.Proof{
			WiresCap:                  common.NewMerkleCap(capHeight),
			PlonkZsPartialProductsCap: common.NewMerkleCap(capHeight),
			QuotientPolysCap:          common.NewMerkleCap(capHeight),
			Openings: common.NewOpeningSet(
				commonData.Config.NumConstants,
				commonData.Config.NumRoutedWires,
				commonData.Config.NumWires,
				commonData.Config.NumChallenges,
				commonData.NumPartialProducts,
				commonData.QuotientDegreeFactor,
			),
			OpeningProof: common.FriProof{
				CommitPhaseMerkleCaps: friCommitPhaseMerkleCaps,
				QueryRoundProofs:      friQueryRoundProofs,
				FinalPoly:             common.NewPolynomialCoeffs(commonData.FriParams.FinalPolyLen()),
			},
		},
		PublicInputs: make([]field.F, commonData.NumPublicInputs),
	}

	return proofInput
}
*/

func (c *VerifierChip) Verify(
	proof common.Proof,
	publicInputs []gl.Variable,
	verifierData common.VerifierOnlyCircuitData,
	commonData common.CommonCircuitData,
) {
	glApi := gl.NewChip(c.api)
	// TODO: Need to range check all the proof and public input elements to make sure they are within goldilocks field

	// Generate the parts of the witness that is for the plonky2 proof input
	publicInputsHash := c.GetPublicInputsHash(publicInputs)
	proofChallenges := c.GetChallenges(proof, publicInputsHash, commonData, verifierData)

	c.plonkChip.Verify(proofChallenges, proof.Openings, publicInputsHash)

	initialMerkleCaps := []common.MerkleCap{
		verifierData.ConstantSigmasCap,
		proof.WiresCap,
		proof.PlonkZsPartialProductsCap,
		proof.QuotientPolysCap,
	}

	// Seems like there is a bug in the emulated field code.
	// Add ZERO to all of the fri challenges values to reduce them.
	proofChallenges.PlonkZeta[0] = glApi.Add(proofChallenges.PlonkZeta[0], gl.Zero())
	proofChallenges.PlonkZeta[1] = glApi.Add(proofChallenges.PlonkZeta[1], gl.Zero())

	proofChallenges.FriChallenges.FriAlpha[0] = glApi.Add(proofChallenges.FriChallenges.FriAlpha[0], gl.Zero())
	proofChallenges.FriChallenges.FriAlpha[1] = glApi.Add(proofChallenges.FriChallenges.FriAlpha[1], gl.Zero())

	for i := 0; i < len(proofChallenges.FriChallenges.FriBetas); i++ {
		proofChallenges.FriChallenges.FriBetas[i][0] = glApi.Add(proofChallenges.FriChallenges.FriBetas[i][0], gl.Zero())
		proofChallenges.FriChallenges.FriBetas[i][1] = glApi.Add(proofChallenges.FriChallenges.FriBetas[i][1], gl.Zero())
	}

	proofChallenges.FriChallenges.FriPowResponse = glApi.Add(proofChallenges.FriChallenges.FriPowResponse, gl.Zero())

	for i := 0; i < len(proofChallenges.FriChallenges.FriQueryIndices); i++ {
		proofChallenges.FriChallenges.FriQueryIndices[i] = glApi.Add(proofChallenges.FriChallenges.FriQueryIndices[i], gl.Zero())
	}

	c.friChip.VerifyFriProof(
		fri.GetFriInstance(&commonData, glApi, proofChallenges.PlonkZeta, commonData.DegreeBits),
		fri.ToFriOpenings(proof.Openings),
		&proofChallenges.FriChallenges,
		initialMerkleCaps,
		&proof.OpeningProof,
	)
}
