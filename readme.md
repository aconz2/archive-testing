This is a little experiment on file archives. I have a use case where I'd like to be able to create a file hierarchy from an archive with the following things in mind:

* decode as fast as possible; I imagine this means spending >99% in kernel
* prioritize decode speed over encode speed
* be able to create the archives fairly easily from eg. javascript
* support linux, so arbitrary byte filenames (roughly up to `PATH_MAX`, but not really caring about that)
* support medium file sizes, so 32 bit 4G is more than enough (these will be sent from the browser, so I'll reject things bigger than some much lower limit)
* support medium number of files/dirs, so maybe 10k ish
  * this means we know / can iterate the input tree in one pass then write out all the data
* extract into a given directory which is assumed empty to begin with, no names should be treated as absolute paths
* be secure! we don't want directory path traversal attacks when we unpack malicious archives
  * it is okay to achieve security without detecting it, so if writing to `../something/sensitive` succeeds but the file is still contained in the unpacking root, then that is okay
* only support directories and regular files and their contents; no links, attrs, times, perms, modes, etc.

# approach

First thing I want to avoid is the unpacker being smart about creating directories as there are so many fiddly bits and potential syscalls to do. So we have the sender send all directory paths in sorted order and with null byte separators. This means we can unconditionally call `mkdir` for each entry and every call should succeed. The only potentially faster thing I can think of (besides `io_uring`) would be something fancy like a bytecode that would tell the unpacker when it is worthwhile to call `chdir`, then a bunch of `mkdir` without the parent prefix. so the instruction stream would be like `pmkdir foo; pmkdir bar; mkdir baz; pop; mkdir buz;` where `pmkdir` makes the dir, pushes the cwd on a stack and changes into it. This creates `foo, foo/bar, foo/bar/baz, foo/buz`. This is a tradeoff in the kernel whether the directory traversal is faster with the full path vs the overhead of calling chdir. AFAIK there is no `mkdirat` like there is `openat` that would let you use the fd of the dir opened with `open(parent, O_PATH)` instead of `chdir`.

The next thing to do is unpack the files. The archive stores all the filenames with null byte separators. There is then a block of u32le file sizes (aligned in the file to alignment 4) so we know how big the data is. The end of the archive is all the file contents stored together. So then we just need an `open`, one or more `write`s and a `close`. Currently the archive is mmap'd in and I'm using `write`, but another thing to try is `copy_file_range`.

For security, the goal is to always unpack the archive under a given directory, not allowing any `../foo` or `/foo` relative or absolute traversals. For directories, we also need to prefix the name with `/destination` because there is no `mkdirat`; this means we have to memcpy every single byte for the directory paths which is boo. For files, there is `openat` which lets us skip the prefixing and there's even `openat2` which gives us `RESOLVE_IN_ROOT` which means `../foo` and `/foo` are always resolved relative to our destination directory, without us having to sanitize or check the input. Why am I so against sanitizing the input? Because that seems easy to mess up and has already resulted in CVE's (`contains_dot_dot` from tar). And alas there is no `mkdirat2` so we still have to sanitize the `mkdir` calls! But we have another hope: the equivalent of `unshare --map-root-user --user chroot destination do-unpack`! Before unpacking, we want to `chroot` into our destination directory so that `../foo` just results in `/foo` and `/foo` is still `/foo`, but is actually `destination/foo`. But `chroot` requires `CAP_SYS_CHROOT` which is usually not a regular user, like uid 1000. Luckily, we can gain this capability if we enter a new user namespace AND use the `uid_map` to map our userid to user 0. That whole dance looks like:

```
mkdir /tmp/destination
strace unshare --map-root-user --user chroot /tmp/destination echo

geteuid()                               = 1000
getegid()                               = 1000
unshare(CLONE_NEWUSER)                  = 0
openat(AT_FDCWD, "/proc/self/uid_map", O_WRONLY) = 3
write(3, "0 1000 1", 8)                 = 8
close(3)                                = 0
openat(AT_FDCWD, "/proc/self/setgroups", O_WRONLY) = 3
write(3, "deny", 4)                     = 4
close(3)                                = 0
openat(AT_FDCWD, "/proc/self/gid_map", O_WRONLY) = 3
write(3, "0 1000 1", 8)                 = 8
close(3)                                = 0
chroot("/tmp/destination")              = 0
chdir("/")                              = 0
```

See `fn chroot` in src/main.rs for the implementation

# benchmarking

Okay to benchmark we'll test a small dir, this repo, and a big dir, the linux 6.2 tree. We'll test a `write` version of this unpacker and a `copy_file_range`. We want to look at time and also syscall counts. The destination directory will be on tmpfs and so will the archives. I want to test tar and cpio, no compression, and filtering out any links.

```
```


# my random notes

```
ls src/*.rs | entr -c bash -c 'cargo build && git ls-files | cargo run create_v0 /tmp/archive.v0'
ls src/*.rs | entr -c bash -c 'cargo build && (cd ../linux; git ls-files | ../archive-testing/target/debug/archive-testing create_v0 /tmp/archive.v0)'
ls src/*.rs | entr -c bash -c '(git ls-files | cargo run create_v0 /tmp/archive.v0) && (rm -rf /tmp/dir; mkdir /tmp/dir; cargo run unp
ack_v0 /tmp/archive.v0 /tmp/dir)'
ls src/*.rs | entr -c bash -c '(git ls-files | cargo run create_v0 /tmp/archive.v0) && (rm -rf /tmp/dir; mkdir /tmp/dir; cargo run unpack_v0 /tmp/archive.v0 /tmp/dir) && tree /tmp/dir && cat /tmp/dir/readme.md'
```

cpio with --make-dirs  archive-testing then linux
  Time (mean ± σ):     701.3 µs ±  43.1 µs    [User: 334.1 µs, System: 485.7 µs]
  Time (mean ± σ):      3.567 s ±  0.010 s    [User: 0.418 s, System: 3.124 s]
