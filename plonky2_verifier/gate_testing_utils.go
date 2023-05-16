package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
)

var localConstants = []QuadraticExtension{
	{NewFieldElement(14938388220067017512), NewFieldElement(6893617978345561255)},
	{NewFieldElement(2858278997849927318), NewFieldElement(14613858972289114497)},
	{NewFieldElement(12010705804054043554), NewFieldElement(17734088886423096402)},
	{NewFieldElement(6471692081681050808), NewFieldElement(18106394403447308154)},
	{NewFieldElement(12558554458272921972), NewFieldElement(2216637096996035026)},
	{NewFieldElement(2742311400964131460), NewFieldElement(9282906066726805869)},
	{NewFieldElement(6596410029573254275), NewFieldElement(10257498171037842553)},
}

var localWires = []QuadraticExtension{
	{NewFieldElement(2324480063341987239), NewFieldElement(988591962437064919)},
	{NewFieldElement(14688677982646642822), NewFieldElement(8146247054257470414)},
	{NewFieldElement(17333596212120632616), NewFieldElement(8229773878724567671)},
	{NewFieldElement(16821804945910820925), NewFieldElement(12343335221440433490)},
	{NewFieldElement(2756227950103887825), NewFieldElement(343560939592426117)},
	{NewFieldElement(16596623007682686427), NewFieldElement(16182492379544649001)},
	{NewFieldElement(11316887259286577994), NewFieldElement(5467115228713222299)},
	{NewFieldElement(1582490957227381752), NewFieldElement(6925101494868390621)},
	{NewFieldElement(17935248409332290352), NewFieldElement(12534157394828412916)},
	{NewFieldElement(1232026497545098356), NewFieldElement(14048694225063532055)},
	{NewFieldElement(11979806059027179452), NewFieldElement(17007628877389084459)},
	{NewFieldElement(6185211824111055171), NewFieldElement(11113325383534952676)},
	{NewFieldElement(5285260129504523793), NewFieldElement(2234312045539869327)},
	{NewFieldElement(5097097637012137260), NewFieldElement(6201025554481621574)},
	{NewFieldElement(6037242957330965254), NewFieldElement(8600833538151893000)},
	{NewFieldElement(1840669856531831838), NewFieldElement(15065652255235975922)},
	{NewFieldElement(12697827657439264676), NewFieldElement(8513261715427030745)},
	{NewFieldElement(17293199904676005799), NewFieldElement(3250033655198439882)},
	{NewFieldElement(15670279238000114139), NewFieldElement(2873593865532946130)},
	{NewFieldElement(8233044221496845350), NewFieldElement(7769536024141251466)},
	{NewFieldElement(7276958187322513627), NewFieldElement(1860660389845587459)},
	{NewFieldElement(9589532469937976759), NewFieldElement(7590567423994010364)},
	{NewFieldElement(16188252206420308967), NewFieldElement(1215332132961798729)},
	{NewFieldElement(4284385291851770933), NewFieldElement(8054708369354118180)},
	{NewFieldElement(951064484118793750), NewFieldElement(14928634967654532194)},
	{NewFieldElement(5756940583948879782), NewFieldElement(16919129773187566805)},
	{NewFieldElement(14616825313554663172), NewFieldElement(14608067953510361893)},
	{NewFieldElement(2218969368435230247), NewFieldElement(8314107073610762130)},
	{NewFieldElement(2846464114111699115), NewFieldElement(1739645682168118162)},
	{NewFieldElement(9428678995108626933), NewFieldElement(18300292734756419913)},
	{NewFieldElement(17837447932135148748), NewFieldElement(16963062756757640776)},
	{NewFieldElement(15769972692897111778), NewFieldElement(11937356836123640190)},
	{NewFieldElement(8427612563992716672), NewFieldElement(6338936101976157422)},
	{NewFieldElement(8087028861430760589), NewFieldElement(15904493721713953322)},
	{NewFieldElement(16852312552899313453), NewFieldElement(12703698940483431753)},
	{NewFieldElement(9385581021480003680), NewFieldElement(16428288666295194603)},
	{NewFieldElement(17228209431960982877), NewFieldElement(7918190884273718559)},
	{NewFieldElement(3132939554659874022), NewFieldElement(14065724777617623144)},
	{NewFieldElement(1997749289316112361), NewFieldElement(9278657719821874692)},
	{NewFieldElement(11261631966308838097), NewFieldElement(17864868364492856478)},
	{NewFieldElement(6870413790049792873), NewFieldElement(7958529866191467568)},
	{NewFieldElement(3285486169947371103), NewFieldElement(13432787563835021279)},
	{NewFieldElement(15050449752793271273), NewFieldElement(18354035013159256035)},
	{NewFieldElement(13156406563219393216), NewFieldElement(2811064537112579464)},
	{NewFieldElement(152960041933474907), NewFieldElement(1638753743319968389)},
	{NewFieldElement(319825484888354934), NewFieldElement(9316401211755928943)},
	{NewFieldElement(16408408071810237531), NewFieldElement(18410352386107353801)},
	{NewFieldElement(11721234235617526034), NewFieldElement(15999840912099509122)},
	{NewFieldElement(6334230580789589688), NewFieldElement(14426162209351753421)},
	{NewFieldElement(958567038590387846), NewFieldElement(8029518124072166613)},
	{NewFieldElement(14177438370769025330), NewFieldElement(16473317446385361345)},
	{NewFieldElement(15581189373117842086), NewFieldElement(5900338653012073386)},
	{NewFieldElement(8240400515986653624), NewFieldElement(14185121622736441262)},
	{NewFieldElement(6679588999186450167), NewFieldElement(7128455250623622155)},
	{NewFieldElement(16252662677474545634), NewFieldElement(11498423056076196888)},
	{NewFieldElement(15806801790824973416), NewFieldElement(2139294885746295937)},
	{NewFieldElement(2686237135450455588), NewFieldElement(11560495253516227160)},
	{NewFieldElement(10794154831626450247), NewFieldElement(14846136074280133457)},
	{NewFieldElement(10904017069956482237), NewFieldElement(16678728929164911588)},
	{NewFieldElement(77097765992419633), NewFieldElement(6037802885211793535)},
	{NewFieldElement(2948949654471962353), NewFieldElement(2821197372203299784)},
	{NewFieldElement(11058031646382030618), NewFieldElement(14661594862905661700)},
	{NewFieldElement(12154711323908739968), NewFieldElement(16167190320499561302)},
	{NewFieldElement(7860977505669195590), NewFieldElement(13935954304018092783)},
	{NewFieldElement(18189874348209070279), NewFieldElement(11538053105967940289)},
	{NewFieldElement(11425397866380016050), NewFieldElement(3629278068857786221)},
	{NewFieldElement(14222050824749623144), NewFieldElement(15140845573600227476)},
	{NewFieldElement(11344695042959853614), NewFieldElement(2169085408567386370)},
	{NewFieldElement(1382814149657132134), NewFieldElement(1236079356280021064)},
	{NewFieldElement(17447449634981200877), NewFieldElement(4036324561038142974)},
	{NewFieldElement(11667566735027246199), NewFieldElement(7504612499562579295)},
	{NewFieldElement(8096661641373469320), NewFieldElement(17495789134569173932)},
	{NewFieldElement(9772815018478920866), NewFieldElement(6155533504741603890)},
	{NewFieldElement(4680980484631369987), NewFieldElement(12005731930547792380)},
	{NewFieldElement(6030057570246380244), NewFieldElement(1574605083038813985)},
	{NewFieldElement(6754716419760683051), NewFieldElement(9739266036232852396)},
	{NewFieldElement(3724513823179248054), NewFieldElement(13013306109228123804)},
	{NewFieldElement(11890451292401098866), NewFieldElement(16486773210504598590)},
	{NewFieldElement(15585701182352051988), NewFieldElement(11720999619266399739)},
	{NewFieldElement(7485278618867936600), NewFieldElement(11145589513887907261)},
	{NewFieldElement(14193072368816296635), NewFieldElement(7323345281142640608)},
	{NewFieldElement(17524516352488247889), NewFieldElement(15683878140283813020)},
	{NewFieldElement(12837567742060157665), NewFieldElement(4718676941458713108)},
	{NewFieldElement(6217075579383787974), NewFieldElement(6370591763549375649)},
	{NewFieldElement(8359486437738096506), NewFieldElement(10778994345307569722)},
	{NewFieldElement(4952581951776675799), NewFieldElement(17817948246329576635)},
	{NewFieldElement(3976052009388288681), NewFieldElement(17849902626188930996)},
	{NewFieldElement(17810794672545767939), NewFieldElement(1041595632469164526)},
	{NewFieldElement(14280479506185077398), NewFieldElement(9432275670660632521)},
	{NewFieldElement(16096793441725012598), NewFieldElement(14080357378312550361)},
	{NewFieldElement(2808358450883300976), NewFieldElement(18155683068497079023)},
	{NewFieldElement(12506615906620507426), NewFieldElement(13547702647793093771)},
	{NewFieldElement(543665817978834688), NewFieldElement(11749575935793871460)},
	{NewFieldElement(14472836352047062696), NewFieldElement(12745333723416264174)},
	{NewFieldElement(12981918713322309538), NewFieldElement(12274815259004888156)},
	{NewFieldElement(8926153023959879624), NewFieldElement(15612804752658609157)},
	{NewFieldElement(15470343302949437595), NewFieldElement(11164995109470525521)},
	{NewFieldElement(10520929231082168869), NewFieldElement(16888496821066277493)},
	{NewFieldElement(1028056151721181243), NewFieldElement(8120934238589042033)},
	{NewFieldElement(1810007995141850479), NewFieldElement(2490559022189551873)},
	{NewFieldElement(1867732552988682347), NewFieldElement(8352749138289783478)},
	{NewFieldElement(1772251986087179577), NewFieldElement(1151343330961505549)},
	{NewFieldElement(14295941257654230218), NewFieldElement(8638985198387420860)},
	{NewFieldElement(582917963870113299), NewFieldElement(13301360102508097820)},
	{NewFieldElement(18438694801095657876), NewFieldElement(2953322262478232169)},
	{NewFieldElement(7603887573063566422), NewFieldElement(6091524026276266924)},
	{NewFieldElement(7184877376568353020), NewFieldElement(5312277526863426709)},
	{NewFieldElement(4845801136589914168), NewFieldElement(1561342471733565936)},
	{NewFieldElement(13089468615522535612), NewFieldElement(4057681051840817565)},
	{NewFieldElement(14153633198781966944), NewFieldElement(11670642633718804558)},
	{NewFieldElement(16238871251946995480), NewFieldElement(9879378414393071037)},
	{NewFieldElement(407815114363153064), NewFieldElement(18417737282937069683)},
	{NewFieldElement(10314092695875136843), NewFieldElement(17129917118418209854)},
	{NewFieldElement(14435763837662532097), NewFieldElement(4319511190642832713)},
	{NewFieldElement(11747855857520646712), NewFieldElement(7041602666708225251)},
	{NewFieldElement(9175192383987399327), NewFieldElement(4409574583823547850)},
	{NewFieldElement(9548913170337855226), NewFieldElement(4160834878925069440)},
	{NewFieldElement(965944482423049129), NewFieldElement(14015844569022395350)},
	{NewFieldElement(17244878179047663844), NewFieldElement(925516683252056953)},
	{NewFieldElement(11530194255376349088), NewFieldElement(3004909091927990154)},
	{NewFieldElement(5197253289126122309), NewFieldElement(4693726439926432566)},
	{NewFieldElement(16039381979512237027), NewFieldElement(8603041366636528085)},
	{NewFieldElement(6094270808101390314), NewFieldElement(13412584619695658458)},
	{NewFieldElement(300463888721818101), NewFieldElement(1345726875223674416)},
	{NewFieldElement(15941208658209056668), NewFieldElement(9615553092932888024)},
	{NewFieldElement(12935711669717280950), NewFieldElement(1779981135440026594)},
	{NewFieldElement(1903849940544955596), NewFieldElement(3220793888228552075)},
	{NewFieldElement(17009281029954729848), NewFieldElement(12717382096012389232)},
	{NewFieldElement(8308499022107883215), NewFieldElement(7238839475668369173)},
	{NewFieldElement(4681909377350889716), NewFieldElement(9121889619872786537)},
	{NewFieldElement(16745334188484332040), NewFieldElement(13880192213923952919)},
	{NewFieldElement(8275654896887061920), NewFieldElement(5378310777055483996)},
	{NewFieldElement(2877567868802486135), NewFieldElement(3737222674819658170)},
	{NewFieldElement(7662876313147287437), NewFieldElement(15849146076823477077)},
	{NewFieldElement(15996655521860650011), NewFieldElement(10796039480722311424)},
	{NewFieldElement(3451129575094269729), NewFieldElement(9506170035703226854)},
}

var publicInputsHash = Hash{ZERO_F, ZERO_F, ZERO_F, ZERO_F}

var constantGateExpectedConstraints = []QuadraticExtension{
	{NewFieldElement(417831337622144221), NewFieldElement(8294314104289740950)},
	{NewFieldElement(10354476116341195774), NewFieldElement(2111251116780372139)},
}

var baseSumGateExpectedConstraints = []QuadraticExtension{
	{NewFieldElement(13342375419378862774), NewFieldElement(2280369543228400622)},
	{NewFieldElement(4343016273263963301), NewFieldElement(8670112296843354731)},
	{NewFieldElement(16450085172304373435), NewFieldElement(9474921066378691247)},
	{NewFieldElement(10825438813181866983), NewFieldElement(4721788102061048468)},
	{NewFieldElement(2653358151822415377), NewFieldElement(16941658162630334598)},
	{NewFieldElement(16109827603357243766), NewFieldElement(2469723755597001985)},
	{NewFieldElement(16092509697995123079), NewFieldElement(15792545805376063500)},
	{NewFieldElement(18220570683647205186), NewFieldElement(15344882637457318583)},
	{NewFieldElement(11198665856327480684), NewFieldElement(5553903935302684834)},
	{NewFieldElement(10482437897580882341), NewFieldElement(8685229612947119045)},
	{NewFieldElement(4559642503814598145), NewFieldElement(10753102667902815825)},
	{NewFieldElement(622804064827561260), NewFieldElement(581766069302707440)},
	{NewFieldElement(18211909441470681488), NewFieldElement(9918892113105798061)},
	{NewFieldElement(17690944039562025874), NewFieldElement(10477359595782407734)},
	{NewFieldElement(10779840836031384949), NewFieldElement(5788395352825863117)},
	{NewFieldElement(16642771945619329948), NewFieldElement(16143638493085149246)},
	{NewFieldElement(4736242245615047143), NewFieldElement(8163893235093339079)},
	{NewFieldElement(1094576462017674831), NewFieldElement(174501253315632830)},
	{NewFieldElement(13301388104345214501), NewFieldElement(10119526634662127335)},
	{NewFieldElement(8813857633984933142), NewFieldElement(3166911591676225444)},
	{NewFieldElement(4484502504021732255), NewFieldElement(1409252568845542666)},
	{NewFieldElement(1370941442659786223), NewFieldElement(17296588456662108571)},
	{NewFieldElement(4569099382027624816), NewFieldElement(17912433869630853419)},
	{NewFieldElement(14131075703244612804), NewFieldElement(3689236699393284763)},
	{NewFieldElement(18110259573622113024), NewFieldElement(6304531968860732013)},
	{NewFieldElement(8367598931797559807), NewFieldElement(15403657336885577186)},
	{NewFieldElement(14940830541973671114), NewFieldElement(7321434648394309094)},
	{NewFieldElement(4391132182759374634), NewFieldElement(5732898826353006639)},
	{NewFieldElement(7456591484914201025), NewFieldElement(18109528517204812723)},
	{NewFieldElement(17161771796959903109), NewFieldElement(13156261145684066101)},
	{NewFieldElement(13536084388374414797), NewFieldElement(2054701847843415519)},
	{NewFieldElement(14910161626746342494), NewFieldElement(16386413929249303239)},
	{NewFieldElement(135663282453455528), NewFieldElement(7326002312332878726)},
}
