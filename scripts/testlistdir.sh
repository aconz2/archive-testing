#!/usr/bin/bash

set -e

cargo build --bin listdir
cargo build --bin listdir --release
cargo build --bin listdir --target x86_64-unknown-linux-musl
cargo build --bin listdir --release --target x86_64-unknown-linux-musl

function straceit() {
    echo $2
    strace -e 'fcntl,getdents64,openat,open,close,fstat,stat,statx' -c $1 $2 . | sha256sum
}
for x in $(find -name listdir); do
    echo "--- $x ---"
    for y in list_dir list_dir2 list_dir_c list_dir_nr list_dir_wd; do
        straceit $x $y
        echo
    done

    echo "==============================================================="
    echo
done
