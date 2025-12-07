# Kaléidoscope

## zerauth

## Kyber

### Debug

```bash
cmake --preset Debug && cmake --build --preset Debug
```

```bash
./build_Debug-zerauth/zerauth
```


### Release

```bash
cmake --preset Release && cmake --build --preset Release
```


```bash
./build_Release-zerauth/zerauth
```

----


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

Proof is (-32FDAF1ABEA6999BF4D484F1101CF6089165896FC74DFCE9FED4D654B3347B226230DBDB06D64419E1E42D9729B2644149E5E724B89CBC6D5B47503AED8EBFFD)
Alice proved to Bob she knows the password
```

### Wasm

```bash
cmake --preset wasm && cmake --build --preset wasm
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


- https://aszepieniec.github.io/stark-anatomy/fri.html
- https://www.alonrosen.net/PAPERS/lattices/description.pdf
- https://github.com/scipr-lab/libfqfft
- https://github.com/scipr-lab/libsnark.git


//
//  openssl ecparam
// -list_curves
- https://eprint.iacr.org/2022/1593.pdf
- http://fc13.ifca.ai/proc/5-1.pdf
- https://sebastiaagramunt.medium.com/discrete-logarithm-problem-and-diffie-hellman-key-exchange-821a45202d26
- https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf
- https://eprint.iacr.org/2022/1593.pdf
- https://datatracker.ietf.org/doc/draft-hao-schnorr/05/
- https://www.rfc-editor.org/rfc/pdfrfc/rfc8235.txt.pdf
- https://asecuritysite.com/zero/dleq_z
- https://github.com/sdiehl/schnorr-nizk
- https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf
