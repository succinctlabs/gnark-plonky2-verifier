package plonky2_verifier

import (
	"encoding/json"
	"fmt"
	. "gnark-ed25519/goldilocks"
	. "gnark-ed25519/poseidon"
	"gnark-ed25519/utils"
	"io/ioutil"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var testCurve = ecc.BN254

type TestChallengerCircuit struct {
	PublicInputs  [3]frontend.Variable
	CircuitDigest [4]frontend.Variable
	WiresCap      [16][4]frontend.Variable
}

func (circuit *TestChallengerCircuit) Define(api frontend.API) error {
	goldilocksApi := NewGoldilocksAPI(api)
	poseidonChip := NewPoseidonChip(api, goldilocksApi)
	challengerChip := NewChallengerChip(api, goldilocksApi, *poseidonChip)

	var circuitDigestGoldilocks [4]GoldilocksElement
	for i := 0; i < 4; i++ {
		circuitDigestGoldilocks[i] = goldilocksApi.FromBinary(api.ToBinary(circuit.CircuitDigest[i], 64)).(GoldilocksElement)
	}

	var publicInputsGoldilocks [3]GoldilocksElement
	for i := 0; i < 3; i++ {
		publicInputsGoldilocks[i] = goldilocksApi.FromBinary(api.ToBinary(circuit.PublicInputs[i], 64)).(GoldilocksElement)
	}

	var wiresCapGoldilocks [16][4]GoldilocksElement
	for i := 0; i < 16; i++ {
		for j := 0; j < 4; j++ {
			wiresCapGoldilocks[i][j] = goldilocksApi.FromBinary(api.ToBinary(circuit.WiresCap[i][j], 64)).(GoldilocksElement)
		}
	}

	publicInputHash := poseidonChip.HashNoPad(publicInputsGoldilocks[:])
	challengerChip.ObserveHash(circuitDigestGoldilocks)
	challengerChip.ObserveHash(publicInputHash)
	challengerChip.ObserveCap(wiresCapGoldilocks[:])

	nbChallenges := 2
	plonkBetas := challengerChip.GetNChallenges(nbChallenges)
	plonkGammas := challengerChip.GetNChallenges(nbChallenges)

	var expectedPlonkBetas [2]frontend.Variable
	expectedPlonkBetas[0] = frontend.Variable("4678728155650926271")
	expectedPlonkBetas[1] = frontend.Variable("13611962404289024887")

	var expectedPlonkGammas [2]frontend.Variable
	expectedPlonkGammas[0] = frontend.Variable("13237663823305715949")
	expectedPlonkGammas[1] = frontend.Variable("15389314098328235145")

	for i := 0; i < 2; i++ {
		goldilocksApi.AssertIsEqual(
			plonkBetas[i],
			goldilocksApi.FromBinary(api.ToBinary(expectedPlonkBetas[i])).(GoldilocksElement),
		)
		goldilocksApi.AssertIsEqual(
			plonkGammas[i],
			goldilocksApi.FromBinary(api.ToBinary(expectedPlonkGammas[i])).(GoldilocksElement),
		)
	}

	return nil
}

func TestDeserializationOfPlonky2Proof(t *testing.T) {
	fibonacciProofPath := "./fibonacci_proof.json"
	jsonFile, err := os.Open(fibonacciProofPath)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result Proof
	json.Unmarshal(byteValue, &result)

	fmt.Println(result.WiresCap)
}

func TestChallengerWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(publicInputs [3]frontend.Variable, circuitDigest [4]frontend.Variable, wiresCap [16][4]frontend.Variable) {
		circuit := TestChallengerCircuit{PublicInputs: publicInputs, CircuitDigest: circuitDigest, WiresCap: wiresCap}
		witness := TestChallengerCircuit{PublicInputs: publicInputs, CircuitDigest: circuitDigest, WiresCap: wiresCap}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}

	publicInputsStr := []string{"0", "1", "3736710860384812976"}
	circuitDigestStr := []string{"7754113318730736048", "18436136620016916513", "18054530212389526288", "5893739326632906028"}
	wiresCapStr := [][]string{
		{"13884351014873073118", "5174249846243191862", "2208632528791973868", "1071582828677910652"},
		{"11475361245556894879", "14867351574926692044", "17013374066934071379", "1027671036932569748"},
		{"5604634992452399010", "3684464596850094189", "5565599237356852406", "4136295609943151014"},
		{"8463721840990025805", "5922588965472526198", "8096699027533803435", "2210089353004111478"},
		{"17531628199677307555", "11513452064460680964", "1482441508929181375", "5139566233781982440"},
		{"13271417993289093233", "17257193898955790413", "16883807866578566670", "7423179920948669117"},
		{"13462567520785358202", "15555103598281658890", "5859961276885232601", "4464568704709749394"},
		{"153012620162729043", "14072764618167122665", "3025694603779494447", "15948104906680148838"},
		{"18050235253694287284", "11467396424826912141", "11302553396166323353", "10976271719722841224"},
		{"15208241660644051470", "8520722208187871063", "10775022596056682771", "16048513824198271730"},
		{"6929477084755896240", "11382029470138215117", "13205948643259905511", "9421863267852221772"},
		{"15449187573546292268", "10216729601353604194", "9493934392442974211", "9848643714440191835"},
		{"2172475758127444753", "16681095938683502188", "9983383760611275566", "2603547977557388755"},
		{"17440301588003279095", "11799356585691460705", "1386003375936412946", "11059100806278290279"},
		{"10758265002546797581", "1374136260999724547", "7200401521491969338", "219493657547391496"},
		{"5995963332181008902", "4442996285152250372", "2005936434281221193", "6869325719052666642"},
	}

	var publicInputs [3]frontend.Variable
	var circuitDigest [4]frontend.Variable
	var wiresCap [16][4]frontend.Variable

	copy(publicInputs[:], utils.StrArrayToFrontendVariableArray(publicInputsStr))
	copy(circuitDigest[:], utils.StrArrayToFrontendVariableArray(circuitDigestStr))
	for i := 0; i < len(wiresCapStr); i++ {
		copy(wiresCap[i][:], utils.StrArrayToFrontendVariableArray(wiresCapStr[i]))
	}

	testCase(publicInputs, circuitDigest, wiresCap)
}
