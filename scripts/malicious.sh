#!/bin/bash

set -e

cargo build --release
bin=$(realpath target/release/archive-testing)

$bin make_malicious /tmp/malicious-archive.v0

rm -rf /tmp/dest
mkdir /tmp/dest

strace $bin unpack_v0 /tmp/malicious-archive.v0 /tmp/dest

ls -l /tmp/dest
