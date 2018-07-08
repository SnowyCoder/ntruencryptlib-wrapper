#!/usr/bin/env bash

require_program() {
    command -v $1 > /dev/null || {
        if (( $# < 2 )); then
            $2=$1
        fi
        echo "Missing program $2"
        echo "Please install it using apt-get, pacman or the tool available in your distro"
        exit 1
    }
}

require_program "autoconf"
require_program "libtoolize" "libtool"

INSTALL=0
CONF_ARGS=""

while (( $# > 0 )); do
    case $1 in
    -install)
        INSTALL=1
        ;;
    -simd)
        CONF_ARGS="$CONF_ARGS --enable-simd"
        ;;
    *)
        echo "Cannot find option $1"
        exit 1
    esac
    shift
done


cd extern/ntruencrypt
./autogen.sh
./configure ${CONF_ARGS}

if (( $INSTALL != 0 )); then
    make check install
else
    make check
    ln .libs/libntruencrypt.so ../../ntruencrypt -f -L
fi
