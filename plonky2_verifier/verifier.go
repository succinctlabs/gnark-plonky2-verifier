package plonky2_verifier

// import (
// 	. "gnark-ed25519/field"
// 	"gnark-ed25519/poseidon"

// 	"github.com/consensys/gnark/frontend"
// )

// type VerifierChip struct {
// 	api          frontend.API
// 	field        frontend.API
// 	poseidonChip poseidon.PoseidonChip
// }

// func (c *VerifierChip) GetPublicInputsHash(publicInputs []F) poseidon.HashOutput {
// 	return c.poseidonChip.HashNoPad(publicInputs)
// }

// func (c *VerifierChip) GetChallenges(proofWithPis ProofWithPublicInputs, publicInputsHash Hash, commonData CommonCircuitData) {
// 	config := commonData.Config
// 	numChallenges := int(config.NumChallenges)
// 	challenger := NewChallengerChip(c.api, c.field, c.poseidonChip)

// 	challenger.ObserveHash(commonData.CircuitDigest)
// 	challenger.ObserveHash(publicInputsHash)
// 	challenger.ObserveCap(proofWithPis.Proof.WiresCap)
// 	plonkBetas := challenger.GetNChallenges(numChallenges)
// 	plonkGammas := challenger.GetNChallenges(numChallenges)

// 	challenger.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
// 	plonkAlphas := challenger.GetNChallenges(numChallenges)

// 	challenger.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
// 	plonkZeta := challenger.GetNChallenges(numChallenges)

// 	challenger.ObserveOpenings(proofWithPis.Proof.Openings)
// }

// func (c *VerifierChip) Verify(proofWithPis ProofWithPublicInputs, verifierData VerifierOnlyCircuitData, commonData CommonCircuitData) {
// 	publicInputsHash := c.GetPublicInputsHash(proofWithPis.PublicInputs)
// 	challenges := c.GetChallenges(proofWithPis, publicInputsHash, commonData)
// }
