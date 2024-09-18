This is a little experiment on file archives. I have a use case where I'd like to be able to create a file hierarchy from an archive with the following things in mind:

* decode as fast as possible; I imagine this means spending >99% in kernel
* prioritize decode speed over encode speed
* be able to create the archives fairly easily from eg. javascript
* support linux, so arbitrary byte filenames (roughly up to `PATH_MAX`, but not really caring about that)
* support medium file sizes, so 32 bit 4G is more than enough (these will be sent from the browser, so I'll reject things bigger than some much lower limit)
* support medium number of files/dirs, so maybe 10k ish
  * this means we know / can iterate the input tree in one pass then write out all the data
* be secure! we don't want directory path traversal attacks when we unpack malicious archives
  * it is okay to achieve security without detecting it, so if writing to `../something/sensitive` succeeds but the file is still contained in the unpacking root, then that is okay
* only support directories and regular files and their contents; no attrs, times, perms, modes, etc.

# approach

First thing I want to avoid is the unpacker being smart about creating directories as there are so many fiddly bits and potential syscalls to do. So we have the sender send all directory paths in sorted order and with null byte separators. Then the filenames also with null byte separators. Then the file sizes as u32le aligned to 4. Then all the file data concat'd together. This archive file can then be mmap'd. Because of the null byte separators, we can pass these strings directly to the syscall either `mkdir` or `open`.


# my random notes

```
ls src/*.rs | entr -c bash -c 'cargo build && git ls-files | cargo run create_v0 /tmp/archive.v0'
ls src/*.rs | entr -c bash -c 'cargo build && (cd ../linux; git ls-files | ../archive-testing/target/debug/archive-testing create_v0 /tmp/archive.v0)'
ls src/*.rs | entr -c bash -c '(git ls-files | cargo run create_v0 /tmp/archive.v0) && (rm -rf /tmp/dir; mkdir /tmp/dir; cargo run unp
ack_v0 /tmp/archive.v0 /tmp/dir)'
ls src/*.rs | entr -c bash -c '(git ls-files | cargo run create_v0 /tmp/archive.v0) && (rm -rf /tmp/dir; mkdir /tmp/dir; cargo run unpack_v0 /tmp/archive.v0 /tmp/dir) && tree /tmp/dir && cat /tmp/dir/readme.md'
```
