module gnark-plonky2-verifier

go 1.19

require (
	github.com/consensys/gnark v0.7.2-0.20220921094618-a121a3074ee8
	github.com/consensys/gnark-crypto v0.8.1-0.20220819163559-143c75519b0e
)

require (
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/google/pprof v0.0.0-20220729232143-a41b82acbcb1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/rs/zerolog v1.28.0 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/exp v0.0.0-20220713135740-79cabaa25d75 // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

// For now, use a forked version of gnark so that the emaulated fields are
// mod'ed when printed.  See here:  https://github.com/kevjue/gnark/commit/0b216679a380b4b8d29f10dd96f34e8a5702463e
replace github.com/consensys/gnark v0.7.2-0.20220921094618-a121a3074ee8 => github.com/kevjue/gnark v0.7.2-0.20221123002814-bcc0d7d32d60
