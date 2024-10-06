#!/bin/bash

# Current pmacct git ref hash
GIT_REPOSITORY=$1
GIT_HASH=$2

mkdir -p /tmp
cd /tmp

echo "Installing pmacct-gauze for pmacct ($GIT_REPOSITORY) ref $GIT_HASH"

# Install Rust and cargo-c and pmacct-gauze
git clone --depth 1 https://github.com/mxyns/pmacct-gauze
cd pmacct-gauze ; rm -rf ./.git ;
sudo apt install -y curl curl clang && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly --target nightly --profile minimal
export PATH="/root/.cargo/bin:${PATH}"
cargo install --git https://github.com/mxyns/cargo-c cargo-c

# Install pmacct for its headers
git clone --recursive $GIT_REPOSITORY pmacct && cd pmacct && git checkout $GIT_HASH

# Manually install libcdada because we want headers to be available
# for pmacct-gauze too without handling CFLAGS and other crap
cd src/external_libs/libcdada
./autogen.sh && ./configure && make install && cd ../../..

# Run a ./configure to generate basic files like pmacct-version.h that
# are required for pmacct-gauze headers to compile
export AVRO_LIBS="-L/usr/local/avro/lib -lavro"
export AVRO_CFLAGS="-I/usr/local/avro/include"
./autogen.sh && ./configure --enable-kafka --enable-redis  \
                              --enable-zmq  --enable-jansson \
                              --enable-avro --enable-serdes
cd ..

# Build pmacct-gauze now that headers are correctly generated
export PMACCT_INCLUDE_DIR=$(pwd)
sudo -E echo "PMACCT_INCLUDE_DIR=$PMACCT_INCLUDE_DIR"
sudo -E /root/.cargo/bin/cargo cinstall --package pmacct-gauze-lib && ldconfig
rm -rf pmacct
