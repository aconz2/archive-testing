#!/bin/bash

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
        time $bin create_v0 /tmp/$dir.v0 < file-list
        echo "--"
    fi

done

popd &>/dev/null

echo '-- testing archive-testing'
taskset -c 0 \
    hyperfine \
    --shell=none \
    --warmup=1 \
    --prepare 'sh -c "rm -rf /tmp/dest; mkdir /tmp/dest"' \
    --command-name tar  'tar --extract --file /tmp/archive-testing.tar --directory /tmp/dest' \
    --command-name cpio './asstdin /tmp/archive-testing.cpio cpio --extract --directory /tmp/dest' \
    --command-name atv0 "$bin unpack_v0 /tmp/archive-testing.v0 /tmp/dest"

echo '-- testing linux'
taskset -c 0 \
    hyperfine \
    --shell=none \
    --warmup=1 \
    --prepare 'sh -c "rm -rf /tmp/dest; mkdir /tmp/dest"' \
    --command-name tar  'tar --extract --file /tmp/linux.tar --directory /tmp/dest' \
    --command-name cpio './asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest' \
    --command-name atv0 "$bin unpack_v0 /tmp/linux.v0 /tmp/dest"

function setup() {
    rm -rf /tmp/dest
    mkdir /tmp/dest
}

function straceit() {
    setup
    taskset -c 0 strace -c $@
}

function perfit() {
    setup
    taskset -c 0 perf stat $@
}

function testit() {
    straceit $@
    perfit $@
}

echo '-- tracing tar'
testit tar --extract --file /tmp/linux.tar --directory /tmp/dest

echo '-- tracing cpio'
testit ./asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest

echo '-- tracing at'
testit $bin unpack_v0 /tmp/linux.v0 /tmp/dest
