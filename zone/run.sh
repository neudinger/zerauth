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
    *)
        echo "Usage: $0 {run|test}"
        exit 1
        ;;
esac