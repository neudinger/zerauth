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


```bash
emsdk install latest
emcmake cmake -B build_add_lib && cmake --build build_add_lib
```


### Release

```bash
cmake --preset Release && cmake --build --preset Release
```


```bash
./build_Release-zerauth/zerauth
```

----

### Wasm

```bash
cmake --preset wasm && cmake --build --preset wasm
```

OR

```bash
emcmake cmake --preset wasm && emcmake cmake --build --preset wasm
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