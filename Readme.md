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


```bash
export OPENSSL_VERSION=3.6.0
wget -qO- \
    https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    | tar xvz --directory ${PWD} \
    && (cd /${PWD}/openssl-${OPENSSL_VERSION}/ \
    && ./Configure linux-generic32 \
    no-docs no-tests no-stdio enable-tfo no-asm \
    no-async no-afalgeng no-threads no-shared \
    --prefix=/usr/local/wasm/openssl \
    --openssldir=/usr/local/wasm/openssl \
    && make CXX=em++ CC=emcc AR=emar RANLIB=emranlib -j$(expr `nproc` + 1) \
    && make install -j$(expr $NPROC + 1))

```