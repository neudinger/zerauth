# Kaleidoscope

## zerauth

## Kyber

### Debug

```bash
cmake --preset Debug && cmake --build --preset Debug -j
```

```bash
./build_Debug-zerauth/zerauth
```

### Release

```bash
cmake --preset Release && cmake --build --preset Release -j
```

```bash
./build_Release-zerauth/zerauth
```

----

## Sigma Protocol

<https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf>

## Statistical Non-Interactive Zero-Knowledge Proofs (SNIZK)

It is Chaum Pedersen Non-Interactive Zero-Knowledge Proof (NIZK) for the equality (EQ) of discrete logarithms (DL) across groups

### Proofs of discrete logarithm equality across groups

sources:

- <https://asecuritysite.com/zero/dleq_z>
- <https://github.com/sdiehl/schnorr-nizk>
- <https://sebastiaagramunt.medium.com/discrete-logarithm-problem-and-diffie-hellman-key-exchange-821a45202d26>

- [Discrete logarithm equality across groups](https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf)
- [Proofs of discrete logarithm equality across groups](https://eprint.iacr.org/2022/1593.pdf)
- [Schnorr Non-interactive Zero-Knowledge Proof](https://datatracker.ietf.org/doc/html/rfc8235)

I implement a Statistical Non-Interactive Zero-Knowledge Proofs (SNIZK) based on the chamum pedersen protocol with equality of discrete logarithms (DL) across groups and nor bullet proof as descibed in the [Proofs of discrete logarithm equality across groups](https://eprint.iacr.org/2022/1593.pdf) or [Discrete logarithm equality across groups](https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf) because these require too much memory and processing power and generate bigger proofs .

This aproach is aroud:

- 100x faster than the Monero approach
- ~20x to 50x faster than IACR
- smaller proofs size for one password commitment

1. Fastest Computation (by 100x).
1. Smallest Proof Size (by 4x).
1. Easiest Implementation.

This is mandatory due to the usage of this library in the web browser and mobile devices and a user dont want to wait too much time to prove their password, a session creation must be fast.

```js

--- json_setup ---
{
  curve_names: [
    "secp256k1"
  ],
  postulate_coordinates: [
    "0324B713EA0F1C962B635D68FE35F1373428B1EA804BF1B6D1E9839CB37827E808"
  ],
  commitment_coordinates: [
    "020E13154ACFEEEE2FE8BC6C023B99CF2181BBFE59F51089EEB5CCDBC2985E443C"
  ],
  salt: "'[X?Zxx`"
}

--- json_setup ---
{
  nonce: "9D00D1C8DD5592860A15CCE56C99E00795A1D4F42CFED69B9ABDC42426ACA6EC",
  challenge: "4C61B00596F30597AADD1C0291643043FEC4FBFD550520A60F74F21E266498C5",
  salt: "'[X?Zxx`"
}

--- json_setup ---
{
  setup: {
    curve_names: [
      "secp256k1"
    ],
    postulate_coordinates: [
      "0324B713EA0F1C962B635D68FE35F1373428B1EA804BF1B6D1E9839CB37827E808"
    ],
    commitment_coordinates: [
      "020E13154ACFEEEE2FE8BC6C023B99CF2181BBFE59F51089EEB5CCDBC2985E443C"
    ],
    salt: "'[X?Zxx`"
  },
  proving: {
    nonce: "9D00D1C8DD5592860A15CCE56C99E00795A1D4F42CFED69B9ABDC42426ACA6EC",
    challenge: "4C61B00596F30597AADD1C0291643043FEC4FBFD550520A60F74F21E266498C5"
  },
  challenge_coordinates: [
    "0210DD107FE092BC633270CC08AEE53FE34A5075D59A8B347D65600AAFAD013284"
  ]
}

Alice proved to Bob she knows the password
```

```js

--- json_setup ---
{
  curve_names: [
    "secp224k1",
    "brainpoolP224t1",
    "brainpoolP320r1"
  ],
  postulate_coordinates: [
    "022593A2AFE91D3065BBA1A1C89EF66673EFB1901F258A1A0D1A6DBA57",
    "03A1368309A7138DCC242238D6FA4E8F700D48546A1A79C7130F42C8FB",
    "02C4F5B7CE5E9ECD06ADDAA266A32349595652F9B9163051985CF283EDE46FE38E9F81E0034B08A414"
  ],
  commitment_coordinates: [
    "02DB1CF4DFAD4DEE133A74EE4A8701B71BBF353FC1F2CF7BC893F5343C",
    "03C88300A6F6A4CD6C84B2F960CA4E1A49F225AA40943DEDC9F8E27160",
    "03808FBE5EDD91FA3BAA07FD87B51D112D18C01AAB15D80FFF82B6C68852805F80EE577861B9E4CCFF"
  ],
  salt: "J9.72>Kb"
}

--- json_setup ---
{
  nonce: "81691EB90D7AC559AF5BBAC75361AC2BD34E1ACFB10FBB8C2073DEF6235AAF7927D49FFD6317F094",
  challenge: "7C1901E066F637441C67059B56F2758CFF8C073B3045E45935EE69325704952F",
  salt: "J9.72>Kb"
}

--- json_setup ---
{
  setup: {
    curve_names: [
      "secp224k1",
      "brainpoolP224t1",
      "brainpoolP320r1"
    ],
    postulate_coordinates: [
      "022593A2AFE91D3065BBA1A1C89EF66673EFB1901F258A1A0D1A6DBA57",
      "03A1368309A7138DCC242238D6FA4E8F700D48546A1A79C7130F42C8FB",
      "02C4F5B7CE5E9ECD06ADDAA266A32349595652F9B9163051985CF283EDE46FE38E9F81E0034B08A414"
    ],
    commitment_coordinates: [
      "02DB1CF4DFAD4DEE133A74EE4A8701B71BBF353FC1F2CF7BC893F5343C",
      "03C88300A6F6A4CD6C84B2F960CA4E1A49F225AA40943DEDC9F8E27160",
      "03808FBE5EDD91FA3BAA07FD87B51D112D18C01AAB15D80FFF82B6C68852805F80EE577861B9E4CCFF"
    ],
    salt: "J9.72>Kb"
  },
  proving: {
    nonce: "81691EB90D7AC559AF5BBAC75361AC2BD34E1ACFB10FBB8C2073DEF6235AAF7927D49FFD6317F094",
    challenge: "7C1901E066F637441C67059B56F2758CFF8C073B3045E45935EE69325704952F"
  },
  challenge_coordinates: [
    "03673C54C0A930E456B0D9524550FC04F13CEF904E36CD236A001DB091",
    "03D68BF71B238F46BA2AFFE101E427B842E69B950E225FF2D55966BBDB",
    "03CCB14E46E571FF0C39E4A5F9035DF5CF660FBB1AAFF204A3D4578D59C2D8DE33C2A1E32061E6F820"
  ]
}

Alice proved to Bob she knows the password
```

### Wasm

```bash
cmake --preset wasm && cmake --build --preset wasm -j
```

OR

```bash
emcmake cmake --preset wasm && emcmake cmake --build --preset wasm
```

```bash
python3 -m http.server -d web/
```

## Build Portable openssl static lib

```bash
export OPENSSL_VERSION=3.6.0
wget -qO- \
    https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    | tar xvz --directory ${PWD} \
    && (cd /${PWD}/openssl-${OPENSSL_VERSION}/ \
    && ./Configure linux-generic32 \
    no-docs no-tests no-stdio enable-tfo no-asm \
    no-async no-afalgeng no-threads no-shared \
    --prefix=/usr/local/wasm/ \
    --openssldir=/usr/local/wasm/ \
    && make CXX=em++ CC=emcc AR=emar RANLIB=emranlib -j$(expr `nproc` + 1) \
    && make install -j$(expr $NPROC + 1))
```

## Zero-Knowledge Succinct Non-Interactive Argument of Knowledge (zkSNARK)

### libfqfft

- <https://github.com/scipr-lab/libfqfft>

```bash
cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -B build
cmake --build build -j
cmake --install build
```

### libsnark

- <https://github.com/scipr-lab/libsnark>

```bash
cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -B build
cmake --build build -j
cmake --install build
```

```bash
g++ snark.cpp -o snark_app -std=c++23 -L /usr/local/lib -lsnark -lff -lgmp -lgmpxx
```

----

## Zero-Knowledge Scalable Transparent Argument of Knowledge (zkSTARK)

### Sources

- <https://aszepieniec.github.io/stark-anatomy/fri.html>
- <https://github.com/scipr-lab/libfqfft>
- <https://github.com/scipr-lab/libsnark.git>

## Lattices zero-knowledge proofs

- <https://www.alonrosen.net/PAPERS/lattices/description.pdf>
- <https://www.rfc-editor.org/rfc/pdfrfc/rfc8235.txt.pdf>


## Basic zero-knowledge proofs with client side password hash

## Fido2 no password zero-knowledge proofs with asymetric key

