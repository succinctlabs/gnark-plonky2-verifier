package plonky2_verifier

import (
	"gnark-plonky2-verifier/field"
	. "gnark-plonky2-verifier/field"
	. "gnark-plonky2-verifier/poseidon"
	"gnark-plonky2-verifier/utils"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestChallengerCircuit struct {
	PublicInputs              [3]frontend.Variable
	CircuitDigest             [4]frontend.Variable
	WiresCap                  [16][4]frontend.Variable
	PlonkZsPartialProductsCap [16][4]frontend.Variable
	QuotientPolysCap          [16][4]frontend.Variable
}

func (circuit *TestChallengerCircuit) Define(api frontend.API) error {
	field := field.NewFieldAPI(api)
	poseidonChip := NewPoseidonChip(api, field)
	challengerChip := NewChallengerChip(api, field, poseidonChip)

	var circuitDigest [4]F
	for i := 0; i < len(circuitDigest); i++ {
		circuitDigest[i] = field.FromBinary(api.ToBinary(circuit.CircuitDigest[i], 64)).(F)
	}

	var publicInputs [3]F
	for i := 0; i < len(publicInputs); i++ {
		publicInputs[i] = field.FromBinary(api.ToBinary(circuit.PublicInputs[i], 64)).(F)
	}

	var wiresCap [16][4]F
	for i := 0; i < len(wiresCap); i++ {
		for j := 0; j < len(wiresCap[0]); j++ {
			wiresCap[i][j] = field.FromBinary(api.ToBinary(circuit.WiresCap[i][j], 64)).(F)
		}
	}

	var plonkZsPartialProductsCap [16][4]F
	for i := 0; i < len(plonkZsPartialProductsCap); i++ {
		for j := 0; j < len(plonkZsPartialProductsCap[0]); j++ {
			plonkZsPartialProductsCap[i][j] = field.FromBinary(api.ToBinary(circuit.PlonkZsPartialProductsCap[i][j], 64)).(F)
		}
	}

	var quotientPolysCap [16][4]F
	for i := 0; i < len(quotientPolysCap); i++ {
		for j := 0; j < len(quotientPolysCap[0]); j++ {
			quotientPolysCap[i][j] = field.FromBinary(api.ToBinary(circuit.QuotientPolysCap[i][j], 64)).(F)
		}
	}

	publicInputHash := poseidonChip.HashNoPad(publicInputs[:])
	challengerChip.ObserveHash(circuitDigest)
	challengerChip.ObserveHash(publicInputHash)
	challengerChip.ObserveCap(wiresCap[:])

	numChallenges := uint64(2)
	plonkBetas := challengerChip.GetNChallenges(numChallenges)
	plonkGammas := challengerChip.GetNChallenges(numChallenges)

	expectedPublicInputHash := [4]F{
		NewFieldElementFromString("8416658900775745054"),
		NewFieldElementFromString("12574228347150446423"),
		NewFieldElementFromString("9629056739760131473"),
		NewFieldElementFromString("3119289788404190010"),
	}

	for i := 0; i < 4; i++ {
		field.AssertIsEqual(publicInputHash[i], expectedPublicInputHash[i])
	}

	expectedPlonkBetas := [2]F{
		NewFieldElementFromString("4678728155650926271"),
		NewFieldElementFromString("13611962404289024887"),
	}

	expectedPlonkGammas := [2]frontend.Variable{
		NewFieldElementFromString("13237663823305715949"),
		NewFieldElementFromString("15389314098328235145"),
	}

	for i := 0; i < 2; i++ {
		field.AssertIsEqual(plonkBetas[i], expectedPlonkBetas[i])
		field.AssertIsEqual(plonkGammas[i], expectedPlonkGammas[i])
	}

	challengerChip.ObserveCap(plonkZsPartialProductsCap[:])
	plonkAlphas := challengerChip.GetNChallenges(numChallenges)

	expectedPlonkAlphas := [2]F{
		NewFieldElementFromString("14505919539124304197"),
		NewFieldElementFromString("1695455639263736117"),
	}

	for i := 0; i < 2; i++ {
		field.AssertIsEqual(plonkAlphas[i], expectedPlonkAlphas[i])
	}

	challengerChip.ObserveCap(quotientPolysCap[:])
	plonkZeta := challengerChip.GetExtensionChallenge()

	expectedPlonkZeta := QuadraticExtension{
		NewFieldElementFromString("14887793628029982930"),
		NewFieldElementFromString("1136137158284059037"),
	}

	for i := 0; i < 2; i++ {
		field.AssertIsEqual(plonkZeta[i], expectedPlonkZeta[i])
	}

	return nil
}

func TestChallengerWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(
		publicInputs [3]frontend.Variable,
		circuitDigest [4]frontend.Variable,
		wiresCap [16][4]frontend.Variable,
		plonkZsPartialProductsCap [16][4]frontend.Variable,
		quotientPolysCap [16][4]frontend.Variable,
	) {
		circuit := TestChallengerCircuit{
			PublicInputs:              publicInputs,
			CircuitDigest:             circuitDigest,
			WiresCap:                  wiresCap,
			PlonkZsPartialProductsCap: plonkZsPartialProductsCap,
			QuotientPolysCap:          quotientPolysCap,
		}
		witness := TestChallengerCircuit{
			PublicInputs:              publicInputs,
			CircuitDigest:             circuitDigest,
			WiresCap:                  wiresCap,
			PlonkZsPartialProductsCap: plonkZsPartialProductsCap,
			QuotientPolysCap:          quotientPolysCap,
		}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
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
	plonkZsPartialProductsCapStr := [][]string{
		{"1209867952068639569", "4958824272276746373", "8278739766347565702", "1966940898171663504"},
		{"12599305286358028697", "8932511136775685440", "5376267558248004641", "6313904687311555884"},
		{"11190791343943249124", "4016631697385248176", "10356629842603047568", "10968099068686195317"},
		{"1963983823153667719", "6333891613271539690", "12318891063769180636", "10443318253972130654"},
		{"7799898099378084347", "2751829638242157622", "8351904444410446701", "5284662773710644867"},
		{"1588568181448440843", "10836321455257423751", "5543952383542989142", "12946954522116753258"},
		{"15710202198621978057", "13746115173212319217", "6103259182317700987", "17589471289629134988"},
		{"12877950969971815168", "4963889190939310439", "8868772654550990048", "11774978531783219015"},
		{"16832740767463005599", "15040340114131672027", "7469306538360789573", "3154855824233652432"},
		{"9383568437827143152", "1741060064145647394", "17668587021570420286", "5241789470902809114"},
		{"2087729156816989530", "8248918881937854542", "8673194597758568216", "10710697836634846115"},
		{"11253371860840267365", "16818881664594712299", "11933553751682199585", "1936353232880935379"},
		{"12163553231829171860", "17244267969759347515", "2003902333564157189", "6934019871173840760"},
		{"2082141893879862527", "18267460725569427782", "1129651898415533808", "14011240934155569890"},
		{"2526273401266876282", "6955959191669943337", "5926536548217021446", "17949337312612691782"},
		{"8858882459906353593", "5813258279939597857", "6320047506247573502", "15969724232572328561"},
	}
	quotientPolysCapStr := [][]string{
		{"9435614145733021495", "1742717829476348934", "11178548223985487003", "14531951007568589725"},
		{"11747844681527676730", "3089691012847802165", "5887135310661642077", "13943570416123664971"},
		{"11150071448774479229", "4486829025930200476", "9369448886033958276", "15757606153229850783"},
		{"14603194410536469617", "11776185929725558373", "3122936423686490326", "10128277488128872810"},
		{"4990578700975083076", "4997575606014863069", "14499603187047727337", "14028694557236527137"},
		{"2279147899956815983", "16034899207717647338", "14763350037932939672", "10075834812570828076"},
		{"1102006741007271956", "15242779529961262072", "6900547375301951311", "8631780317175902419"},
		{"6299112770394539219", "6297397453582105768", "14148031335065995704", "3794733067587629405"},
		{"7891039548997763820", "4260484126440019022", "6493066317319943586", "14775252570136307979"},
		{"10790514248728420789", "14444029601980227412", "17514190309172155536", "12973059492411164965"},
		{"8940755416742726696", "8469566845539112244", "7642612722784522739", "15276772682665052607"},
		{"18306931819862706026", "14374659904694625207", "8609543532143656606", "17350044275494282679"},
		{"9062024023737444614", "13780128979028684176", "6115495431779737008", "7170446003855284754"},
		{"6191400598853400595", "7806485717076924017", "3225145303141729264", "3644550749005104128"},
		{"15759718266801608721", "2406060174022670585", "15679263832775538866", "18066847192985300443"},
		{"9184823221361582966", "4767786405185004644", "9827047623720647370", "993615002460432327"},
	}

	var publicInputs [3]frontend.Variable
	var circuitDigest [4]frontend.Variable
	var wiresCap [16][4]frontend.Variable
	var plonkZsPartialProductsCap [16][4]frontend.Variable
	var quotientPolysCap [16][4]frontend.Variable

	copy(publicInputs[:], utils.StrArrayToFrontendVariableArray(publicInputsStr))
	copy(circuitDigest[:], utils.StrArrayToFrontendVariableArray(circuitDigestStr))
	for i := 0; i < len(wiresCapStr); i++ {
		copy(wiresCap[i][:], utils.StrArrayToFrontendVariableArray(wiresCapStr[i]))
	}
	for i := 0; i < len(plonkZsPartialProductsCapStr); i++ {
		copy(plonkZsPartialProductsCap[i][:], utils.StrArrayToFrontendVariableArray(plonkZsPartialProductsCapStr[i]))
	}
	for i := 0; i < len(quotientPolysCapStr); i++ {
		copy(quotientPolysCap[i][:], utils.StrArrayToFrontendVariableArray(quotientPolysCapStr[i]))
	}

	testCase(publicInputs, circuitDigest, wiresCap, plonkZsPartialProductsCap, quotientPolysCap)
}
