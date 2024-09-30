#!/bin/bash

function header() {
    echo
    echo "============================== $1 =============================="
    echo
}

set -e

cargo build --release
gcc -O2 -o asstdin src/asstdin.c

bin=$(realpath target/release/archive-testing)

pushd . &>/dev/null

for dir in linux archive-testing; do
    cd ~/Repos/$dir

    find -type l -printf '%P\n' > filter-links
    git ls-files | grep -v -F --file filter-links | sort > file-list
    $bin list_dirs < file-list > dir-list

    if [ ! -f /tmp/$dir.tar ]; then
        echo "-- creating $dir tar"
        time tar --create --file /tmp/$dir.tar --files-from file-list
        echo "--"
    fi

    if  [ ! -f /tmp/$dir.cpio ]; then
        echo "-- creating $dir cpio"
        time cpio --create --format newc > /tmp/$dir.cpio < <(cat dir-list file-list)
        echo "--"
    fi

    if [ ! -f /tmp/$dir.v0 ]; then
        echo "-- creating $dir v0"
        time $bin pack_v0 /tmp/$dir.v0 < file-list
        echo "--"
    fi

done

popd &>/dev/null

header 'hyperfine archive-testing'
taskset -c 2 \
    hyperfine \
    --shell=none \
    --warmup=1 \
    --prepare 'sh -c "rm -rf /tmp/dest; mkdir /tmp/dest"' \
    --command-name tar    'tar --extract --file /tmp/archive-testing.tar --directory /tmp/dest' \
    --command-name cpio   './asstdin /tmp/archive-testing.cpio cpio --extract --directory /tmp/dest' \
    --command-name atv0   "$bin unpack_v0 /tmp/archive-testing.v0 /tmp/dest" \
    --command-name atv0cf "$bin unpack_v0 /tmp/archive-testing.v0 /tmp/dest copy_file_range"

header 'hyperfine linux'
taskset -c 2 \
    hyperfine \
    --shell=none \
    --warmup=1 \
    --prepare 'sh -c "rm -rf /tmp/dest; mkdir /tmp/dest"' \
    --command-name tar    'tar --extract --file /tmp/linux.tar --directory /tmp/dest' \
    --command-name cpio   './asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest' \
    --command-name atv0   "$bin unpack_v0 /tmp/linux.v0 /tmp/dest" \
    --command-name atv0cf "$bin unpack_v0 /tmp/linux.v0 /tmp/dest copy_file_range"

function setup() {
    rm -rf /tmp/dest
    mkdir /tmp/dest
}

function straceit() {
    setup
    taskset -c 2 strace -c $@
}

function perfit() {
    setup
    taskset -c 2 perf stat $@
}

function testit() {
    straceit $@
    perfit $@
}

header 'tracing tar linux'
testit tar --extract --file /tmp/linux.tar --directory /tmp/dest

header 'tracing cpio linux'
testit ./asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest

header 'tracing atv0 linux'
testit $bin unpack_v0 /tmp/linux.v0 /tmp/dest

header 'tracing atv0cf linux'
testit $bin unpack_v0 /tmp/linux.v0 /tmp/dest copy_file_range
