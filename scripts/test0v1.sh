#!/bin/bash

function header() {
    echo
    echo "============================== $1 =============================="
    echo
}

set -e

cargo build --release &> /dev/null

bin=$(realpath target/release/archive-testing)

pushd . &>/dev/null

for dir in linux archive-testing; do
    cd ~/Repos/$dir

    if [ ! -f /tmp/$dir.tar ]; then
        git archive HEAD > /tmp/$dir.tar
    fi

    if [ ! -d /tmp/$dir.copy ]; then
        mkdir /tmp/$dir.copy
        tar --extract --file $desttar --directory /tmp/$dir.copy
    fi

    if [ ! -f /tmp/$dir.v0 ]; then
        cd /tmp/$dir.copy
        $bin pack_v0 /tmp/$dir.v0 < <(find -type f -printf '%P\n')
    fi

done

popd &>/dev/null

function inspectdir() {
    cat <(cd $1 && find -type f -exec sha256sum '{}' '+' | sort) <(cd $1 && find -type d | sort)
}

function hashdir() {
    inspectdir $1 | sha256sum
}

function setup() {
    rm -rf /tmp/dest
    mkdir /tmp/dest
}

function checkdest() {  # <name> <command>
    setup
    eval $2 &>/dev/null
    #inspectdir /tmp/dest > /tmp/$1.inspection
    h=$(hashdir /tmp/dest)
    printf "%18s %s\n" "$1" "$h"
}

function hyperfinepack() {
    dir=$1

    header "pack $dir"

    taskset -c 2 \
        hyperfine \
        --shell=none \
        --warmup=1 \
        --command-name tar "tar --create --file /tmp/$dir.testing.tar /tmp/$dir.copy" \
        --command-name atv1 "$bin pack_v1 /tmp/$dir.copy /tmp/$dir.v1"
}

function hyperfineunpack() {
    dir=$1

    header "unpack $dir"

    taskset -c 2 \
        hyperfine \
        --shell=none \
        --warmup=1 \
        --prepare 'sh -c "rm -rf /tmp/dest && mkdir /tmp/dest"' \
        --command-name tar "tar --extract --file /tmp/$dir.tar --directory /tmp/dest" \
        --command-name atv0 "$bin unpack_v0 /tmp/$dir.v0 /tmp/dest" \
        --command-name atv1 "$bin unpack_v1 /tmp/$dir.v1 /tmp/dest"
}

for dir in archive-testing linux; do
    # hyperfinepack $dir
    # hyperfineunpack $dir

    h=$(hashdir /tmp/$dir.copy)
    # inspectdir /tmp/$dir.copy > /tmp/$dir.copy.inspection
    printf "%18s %s\n" "expected" "$h"
    #checkdest tar "tar --extract --file /tmp/$dir.tar --directory /tmp/dest"
    #checkdest unpack_v0 "$bin unpack_v0 /tmp/$dir.v0 /tmp/dest"
    checkdest unpack_v1 "$bin unpack_v1 /tmp/$dir.v1 /tmp/dest"
    checkdest unpack_v1_ring "$bin unpack_v1_ring /tmp/$dir.v1 /tmp/dest"
done


function straceit() {
    core=$1
    shift
    setup
    taskset -c $core strace -c $@
}

function perfit() {
    core=$1
    shift
    setup
    taskset -c $core perf stat $@
}

function testit() {
    #straceit $@
    perfit $@
}

# header 'tracing atv0 archive-testing'
# testit 2 $bin unpack_v0 /tmp/archive-testing.v0 /tmp/dest
#
# header 'tracing atv1 archive-testing'
# testit 2 $bin unpack_v1 /tmp/archive-testing.v1 /tmp/dest
#
# header 'tracing atv0 linux'
# testit 2 $bin unpack_v0 /tmp/linux.v0 /tmp/dest
#
# header 'tracing atv1 linux'
# testit 2 $bin unpack_v1 /tmp/linux.v1 /tmp/dest

for core in 2 2-3 2-4 2-6 2-8 2-16 2-32; do
    header "tracing atv1_ring linux $core"
    perfit $core $bin unpack_v1_ring /tmp/linux.v1 /tmp/dest
done
