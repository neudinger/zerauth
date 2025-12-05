# Kaléidoscope

## zerauth

## Kyber


```bash
cmake --preset Debug
emcmake cmake --preset wasm
```

```bash
cmake --build --preset Debug
emcmake cmake --build --preset wasm
```


```bash
ln --symbolic --force build_Debug-mchub/compile_commands.json compile_commands.json
```

```bash
./build_Debug-mchub/zerauth
```

```bash
emsdk install latest
emcmake cmake -B build_add_lib && cmake --build build_add_lib
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


## Build Drogon

```bash
git clone \
    --depth 1 \
    --branch v1.9.11 \
    --recursive https://github.com/drogonframework/drogon \
cmake -G Ninja -S drogon -B build-drogon -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
cmake --build build-drogon --parallel $(expr $NPROC + 1) \
cmake --install build-drogon
```

- https://aszepieniec.github.io/stark-anatomy/fri.html
- https://www.alonrosen.net/PAPERS/lattices/description.pdf
- https://github.com/scipr-lab/libfqfft
- https://github.com/scipr-lab/libsnark.git
