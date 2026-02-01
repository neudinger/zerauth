#!/bin/sh

case $1 in
    run)
        zig build run
        ;;
    build)
        zig build
        ;;
    help)
        zig build -h
        ;;
    test)
        zig build test
        ;;
    wasm)
        zig build wasm
        ;;
    serve)
        cp zig-out/web/zone.wasm zone/web/
        python3 -m http.server -d zone/web
        ;;
    *)
        echo "Usage: $0 {run|test|wasm}"
        exit 1
        ;;
esac