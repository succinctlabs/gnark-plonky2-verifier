package plonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type TestChallengerCircuit struct {
	PublicInputs              []field.F
	CircuitDigest             poseidon.PoseidonBN128HashOut
	WiresCap                  [16]poseidon.PoseidonBN128HashOut
	PlonkZsPartialProductsCap [16]poseidon.PoseidonBN128HashOut
	QuotientPolysCap          [16]poseidon.PoseidonBN128HashOut
}

func (circuit *TestChallengerCircuit) Define(api frontend.API) error {
	fieldAPI := field.NewFieldAPI(api)
	degreeBits := 3
	qeAPI := field.NewQuadraticExtensionAPI(api, fieldAPI, uint64(degreeBits))
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	poseidonBN128Chip := poseidon.NewPoseidonBN128Chip(api, fieldAPI)
	challengerChip := NewChallengerChip(api, fieldAPI, poseidonChip, poseidonBN128Chip)

	challengerChip.ObserveBN128Hash(circuit.CircuitDigest)
	publicInputHash := poseidonChip.HashNoPad(circuit.PublicInputs[:])
	challengerChip.ObserveHash(publicInputHash)
	challengerChip.ObserveCap(circuit.WiresCap[:])

	numChallenges := uint64(2)
	plonkBetas := challengerChip.GetNChallenges(numChallenges)
	plonkGammas := challengerChip.GetNChallenges(numChallenges)

	expectedPublicInputHash := [4]field.F{
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
	}

	for i := 0; i < 4; i++ {
		fieldAPI.AssertIsEqual(publicInputHash[i], expectedPublicInputHash[i])
	}

	expectedPlonkBetas := [2]field.F{
		field.NewFieldConstFromString("17615363392879944733"),
		field.NewFieldConstFromString("9422446877322953047"),
	}

	expectedPlonkGammas := [2]field.F{
		field.NewFieldConstFromString("15174493176564484303"),
		field.NewFieldConstFromString("6175150444166239851"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkBetas[i], expectedPlonkBetas[i])
		fieldAPI.AssertIsEqual(plonkGammas[i], expectedPlonkGammas[i])
	}

	challengerChip.ObserveCap(circuit.PlonkZsPartialProductsCap[:])
	plonkAlphas := challengerChip.GetNChallenges(numChallenges)

	expectedPlonkAlphas := [2]field.F{
		field.NewFieldConstFromString("9276470834414745550"),
		field.NewFieldConstFromString("5302812342351431915"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkAlphas[i], expectedPlonkAlphas[i])
	}

	challengerChip.ObserveCap(circuit.QuotientPolysCap[:])
	plonkZeta := challengerChip.GetExtensionChallenge()

	expectedPlonkZeta := field.QuadraticExtension{
		field.NewFieldConstFromString("3892795992421241388"),
		field.NewFieldConstFromString("15786647757418200302"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkZeta[i], expectedPlonkZeta[i])
	}

	return nil
}

func StringToBN128Hash(hashStr string) poseidon.PoseidonBN128HashOut {
	hashBigInt, ok := new(big.Int).SetString(hashStr, 10)
	if !(ok) {
		panic("Invalid hash: " + hashStr)
	}

	hashVar := frontend.Variable(*hashBigInt)
	return poseidon.PoseidonBN128HashOut(hashVar)
}

func TestChallengerWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(
		publicInputs []field.F,
		circuitDigest poseidon.PoseidonBN128HashOut,
		wiresCap [16]poseidon.PoseidonBN128HashOut,
		plonkZsPartialProductsCap [16]poseidon.PoseidonBN128HashOut,
		quotientPolysCap [16]poseidon.PoseidonBN128HashOut,
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
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	publicInputs := []field.F{}

	circuitDigest := StringToBN128Hash("11532502846882484230992726008257788785937565673229400981185786126842727172973")

	wiresCaps := [16]poseidon.PoseidonBN128HashOut{}
	wiresCaps[0] = StringToBN128Hash("6232016528318542211523647364792867346449137823066292895075623303633330508214")
	wiresCaps[1] = StringToBN128Hash("3849229275985461680629770572508259203226163621677714310355251582693130685288")
	wiresCaps[2] = StringToBN128Hash("5987556171512366759354088598227343740440477791444099795740854232780130336082")
	wiresCaps[3] = StringToBN128Hash("8523377779888975334090507575349048869294640263235559121841789718805736414837")
	wiresCaps[4] = StringToBN128Hash("4173305429039088756536564029627250985745421317354666614089039608061166671898")
	wiresCaps[5] = StringToBN128Hash("19514742808406256372169729907222415291809011606011679387563713660256488346125")
	wiresCaps[6] = StringToBN128Hash("8519703011007005463193900985655355044586093539828702987016626948657512235078")
	wiresCaps[7] = StringToBN128Hash("13337062986664638507390757043422262298890182385759661595000247205380836291424")
	wiresCaps[8] = StringToBN128Hash("13956988298720968721248573872513053256190487207048215310365406791617256823071")
	wiresCaps[9] = StringToBN128Hash("4139118776078237399422219240136866906229498819930564462151328936368637474741")
	wiresCaps[10] = StringToBN128Hash("20010683036854145765538326917745039166608941517703057250025522185331298063240")
	wiresCaps[11] = StringToBN128Hash("16542849340693186579674885260236043503488748690860552251132996633211111581047")
	wiresCaps[12] = StringToBN128Hash("15340310232736118098606223218073833983285921571850333937460777227732109309104")
	wiresCaps[13] = StringToBN128Hash("14370557250059545670244193708996703450518439828341533154117610442161777001185")
	wiresCaps[14] = StringToBN128Hash("18844434454299441334771065219656682212700835025465734281792408139929868142021")
	wiresCaps[15] = StringToBN128Hash("19676343740377898318702605893881480074303742058989194823248293456630167789460")

	plonkZsPartialProductsCaps := [16]poseidon.PoseidonBN128HashOut{}
	plonkZsPartialProductsCaps[0] = StringToBN128Hash("18630303757724954689095079665308152603926320437432442392614316813333911252124")
	plonkZsPartialProductsCaps[1] = StringToBN128Hash("1941509032097423911575973752610668722198580889286836043016771886256831254944")
	plonkZsPartialProductsCaps[2] = StringToBN128Hash("6147898094056673441182607282006528423230906496770003193057422314911254596722")
	plonkZsPartialProductsCaps[3] = StringToBN128Hash("8711744418341460096856191310559061094028644913424948320707020455945693390966")
	plonkZsPartialProductsCaps[4] = StringToBN128Hash("3170507894509162329082713944669012510679535839018490515228566075949014704871")
	plonkZsPartialProductsCaps[5] = StringToBN128Hash("9513443633020527244719737008971091746535961947215556968735061932963144145728")
	plonkZsPartialProductsCaps[6] = StringToBN128Hash("16440622144490342815400399751667969445057099157732990266662948140364680211732")
	plonkZsPartialProductsCaps[7] = StringToBN128Hash("16904904288584890809819587275120157893767917607795020298373538872373275028362")
	plonkZsPartialProductsCaps[8] = StringToBN128Hash("1322883689945010694042124537248103086068476085787048131689196755087178475099")
	plonkZsPartialProductsCaps[9] = StringToBN128Hash("3859729225679954076862546769780866075152550721517632074656261209033111218654")
	plonkZsPartialProductsCaps[10] = StringToBN128Hash("5995885491698588595978721670502011088690021401297557688057158353938846681398")
	plonkZsPartialProductsCaps[11] = StringToBN128Hash("16957177478856199232404038751327729781816109007496656232207408246975862260922")
	plonkZsPartialProductsCaps[12] = StringToBN128Hash("9422393668093911702915740702404346320943009100616501740579421944206639410155")
	plonkZsPartialProductsCaps[13] = StringToBN128Hash("15680345727093646870610240619814271686346382346107751208797654607051065248818")
	plonkZsPartialProductsCaps[14] = StringToBN128Hash("4939261448468032698521878059774016528161329965101885352386001950329280576201")
	plonkZsPartialProductsCaps[15] = StringToBN128Hash("7003946111898359335505647195128523292498498760325513092978040051648331398446")

	quotientPolysCaps := [16]poseidon.PoseidonBN128HashOut{}
	quotientPolysCaps[0] = StringToBN128Hash("3918560082526903400389798118659365477465402367561322989181693953047280669646")
	quotientPolysCaps[1] = StringToBN128Hash("496966935842756068593963213547105605432646958081400837931911611833297095727")
	quotientPolysCaps[2] = StringToBN128Hash("8683297895986438077633020202252074142721819824824948690853505463451806801507")
	quotientPolysCaps[3] = StringToBN128Hash("14623770060934618886104076268225324888644340537717836901769942847173950269850")
	quotientPolysCaps[4] = StringToBN128Hash("902377468311802642056170073282349607767917979325737018777782566011948776523")
	quotientPolysCaps[5] = StringToBN128Hash("12124340721627925810131860890689432371048624670798932303474977401990312142398")
	quotientPolysCaps[6] = StringToBN128Hash("21656753786114693289615694183370749990935753681953197920766927707640495235100")
	quotientPolysCaps[7] = StringToBN128Hash("4651674172794111060599611529192263627230814664669763852917839857516619530510")
	quotientPolysCaps[8] = StringToBN128Hash("13161231355626784301812735677481006076469384200800574341495987998366265598910")
	quotientPolysCaps[9] = StringToBN128Hash("20853590455948262404101100028402584187982204016660952863575312077951992942329")
	quotientPolysCaps[10] = StringToBN128Hash("742867642166478273564934628555265381154191517824405375118170559554873960389")
	quotientPolysCaps[11] = StringToBN128Hash("17617970388755497287414457313283777609067524774358298322461931046141926005038")
	quotientPolysCaps[12] = StringToBN128Hash("55496208750959228576253470708262329602643441253143570259294790484739321332")
	quotientPolysCaps[13] = StringToBN128Hash("18450079114184018679423491604333957974306902732410122012117555285853099024676")
	quotientPolysCaps[14] = StringToBN128Hash("14403337493956171864251492809058241138806636992110526018123749007090024780352")
	quotientPolysCaps[15] = StringToBN128Hash("252265115458024097842043026135110356285192501597856208375838682286051476335")

	testCase(publicInputs, circuitDigest, wiresCaps, plonkZsPartialProductsCaps, quotientPolysCaps)
}
