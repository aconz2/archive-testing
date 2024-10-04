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

First thing I want to avoid is the unpacker being smart about creating directories as there are so many fiddly bits and potential syscalls to do. So we have the sender send all directory paths in sorted order and with null byte separators. This means we can unconditionally call `mkdir` for each entry and every call should succeed. The only potentially faster thing I can think of (besides `io_uring`) would be something fancy like a bytecode that would tell the unpacker when it is worthwhile to call `open(parent, O_PATH)`, then a bunch of `mkdirat` without the parent prefix. so the instruction stream would be like `pmkdir foo; pmkdir bar; mkdir baz; pop; mkdir buz;` where `pmkdir` makes the dir, opens it as a fd,, pushes the cwd on a stack and changes into it; then use `mkdirat` with a shortened path instead of the full path. This creates `foo, foo/bar, foo/bar/baz, foo/buz`. This is a tradeoff in the kernel whether the directory traversal is faster with the full path vs the overhead of calling open.

The next thing to do is unpack the files. The archive stores all the filenames with null byte separators. There is then a block of u32le file sizes (aligned in the file to alignment 4) so we know how big the data is. The end of the archive is all the file contents stored together. So then we just need an `open`, one or more `write`s and a `close`. Currently the archive is mmap'd in and I'm using `write`, but another thing to try is `copy_file_range`.

For security, the goal is to always unpack the archive under a given directory, not allowing any `../foo` or `/foo` relative or absolute traversals. For files, there is `openat2` which gives us `RESOLVE_IN_ROOT` which means `../foo` and `/foo` are always resolved relative to our destination directory, without us having to sanitize or check the input. But there isn't a `mkdirat2` so we would have to sanitize the dir paths. Why am I so against sanitizing the input? Because that seems easy to mess up and has already resulted in CVE's (`contains_dot_dot` from tar). But we have another hope: the equivalent of `unshare --map-root-user --user chroot destination do-unpack`! Before unpacking, we want to `chroot` into our destination directory so that `../foo` just results in `/foo` and `/foo` is still `/foo`, but is actually `destination/foo`. But `chroot` requires `CAP_SYS_CHROOT` which is usually not a regular user, like uid 1000. Luckily, we can gain this capability if we enter a new user namespace AND use the `uid_map` to map our userid to user 0. That whole dance looks like:

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

Okay to benchmark we'll test a small dir, this repo, and a big dir, the linux 6.2 tree. We'll test a `write` version of this unpacker and a `copy_file_range`. We want to look at time and also syscall counts. The destination directory will be on tmpfs and so will the archives. I want to test tar and cpio, no compression, and filtering out any links. I've created the cpio arhive with all the directories up front just like this archiver to give a more fair comparison. If you only give it a list of files, it won't create the directories unless you also pass the `--make-directories`.

And if you read the test script, you'll see I am using a wrapper `src/asstdin.c` to redirect stdin so we don't have to use the shell with hyperfine for cpio.

Note that I added a small patch to `perf` to give the user/sys breakdown with percentages. Tbd if I can figure out how to submit it.

<details>

```diff
--- a/tools/perf/util/stat-display.c
+++ b/tools/perf/util/stat-display.c
@@ -1256,10 +1256,12 @@ static void print_footer(struct perf_stat_config *config)
                if (config->ru_display) {
                        double ru_utime = timeval2double(&config->ru_data.ru_utime);
                        double ru_stime = timeval2double(&config->ru_data.ru_stime);
+                       double ru_utime_p = ru_utime / total * 100;
+                       double ru_stime_p = ru_stime / total * 100;

                        fprintf(output, "\n\n");
-                       fprintf(output, " %17.9f seconds user\n", ru_utime);
-                       fprintf(output, " %17.9f seconds sys\n", ru_stime);
+                       fprintf(output, " %17.9f seconds user (%6.2f%%)\n", ru_utime, ru_utime_p);
+                       fprintf(output, " %17.9f seconds sys  (%6.2f%%)\n", ru_stime, ru_stime_p);
                }
        } else {
                double sd = stddev_stats(config->walltime_nsecs_stats) / NSEC_PER_SEC;
```

</details>

Here are the results from `./scripts/test.sh`. This is only testing the extraction process. `atv0` is using `write` and `atv0cf` is using `copy_file_range` to write the file contents. That acronym is `archive-testing-v0` (though I haven't tested any other version yet). Updated to test out `close_range` and have just left that only under the version using `write`.

<details>

<summary>full results</summary>

```
-- for linux
there are 5136 dirs
there are 79455 files
total bytes of data 1307391304
filenames len 3044051
dirsb len 144071

-- for archive-testing
there are 2 dirs
there are 4 files
total bytes of data 38216
filenames len 49
dirsb len 12
```

```
============================== hyperfine archive-testing ==============================

Benchmark 1: tar
  Time (mean ± σ):       1.3 ms ±   0.0 ms    [User: 0.3 ms, System: 0.9 ms]
  Range (min … max):     1.3 ms …   1.5 ms    916 runs

  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.

Benchmark 2: cpio
  Time (mean ± σ):     855.2 µs ±  25.4 µs    [User: 256.8 µs, System: 538.0 µs]
  Range (min … max):   818.0 µs … 957.0 µs    1100 runs

  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.

Benchmark 3: atv0
  Time (mean ± σ):     576.3 µs ±  28.7 µs    [User: 274.0 µs, System: 240.9 µs]
  Range (min … max):   546.9 µs … 704.7 µs    1189 runs

  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.

Benchmark 4: atv0cf
  Time (mean ± σ):     580.7 µs ±  28.2 µs    [User: 273.2 µs, System: 246.0 µs]
  Range (min … max):   549.3 µs … 696.8 µs    1170 runs

  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.

Summary
  atv0 ran
    1.01 ± 0.07 times faster than atv0cf
    1.48 ± 0.09 times faster than cpio
    2.32 ± 0.13 times faster than tar

============================== hyperfine linux ==============================

Benchmark 1: tar
  Time (mean ± σ):      1.383 s ±  0.004 s    [User: 0.094 s, System: 1.280 s]
  Range (min … max):    1.375 s …  1.389 s    10 runs

Benchmark 2: cpio
  Time (mean ± σ):      3.563 s ±  0.004 s    [User: 0.403 s, System: 3.137 s]
  Range (min … max):    3.556 s …  3.572 s    10 runs

Benchmark 3: atv0
  Time (mean ± σ):      1.122 s ±  0.005 s    [User: 0.012 s, System: 1.103 s]
  Range (min … max):    1.111 s …  1.127 s    10 runs

Benchmark 4: atv0cf
  Time (mean ± σ):      1.123 s ±  0.001 s    [User: 0.015 s, System: 1.102 s]
  Range (min … max):    1.120 s …  1.124 s    10 runs

Summary
  atv0 ran
    1.00 ± 0.00 times faster than atv0cf
    1.23 ± 0.01 times faster than tar
    3.18 ± 0.02 times faster than cpio

============================== tracing tar linux ==============================

% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 37.73    1.026131           5    205097           write
 26.93    0.732414           8     84022      4499 openat
 16.49    0.448566           3    133662           read
  8.15    0.221561           2     79455           utimensat
  7.81    0.212441           2     79524           close
  2.87    0.078098           4     18186     13050 mkdirat
  0.00    0.000111           2        47           mmap
  0.00    0.000105           2        48           fstat
  0.00    0.000071           3        20           statx
  0.00    0.000020           1        11           mprotect
  0.00    0.000019           6         3           newfstatat
  0.00    0.000013           2         6         4 prctl
  0.00    0.000008           2         3           fcntl
  0.00    0.000007           3         2           munmap
  0.00    0.000005           2         2           rt_sigprocmask
  0.00    0.000005           2         2           umask
  0.00    0.000004           2         2           lseek
  0.00    0.000003           3         1           futex
  0.00    0.000002           2         1           rt_sigaction
  0.00    0.000002           2         1           geteuid
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         2         2 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         3         1 statfs
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ----------------
100.00    2.719586           4    600112     17556 total

 Performance counter stats for 'tar --extract --file /tmp/linux.tar --directory /tmp/dest':

          1,393.01 msec task-clock:u                     #    1.002 CPUs utilized
                 0      context-switches:u               #    0.000 /sec
                 0      cpu-migrations:u                 #    0.000 /sec
               154      page-faults:u                    #  110.552 /sec
       336,905,533      cycles:u                         #    0.242 GHz
       144,222,037      stalled-cycles-frontend:u        #   42.81% frontend cycles idle
       489,744,079      instructions:u                   #    1.45  insn per cycle
                                                  #    0.29  stalled cycles per insn
        95,070,579      branches:u                       #   68.248 M/sec
         3,007,216      branch-misses:u                  #    3.16% of all branches

       1.389996408 seconds time elapsed

       0.093593000 seconds user (  6.75%)
       1.293657000 seconds sys  ( 93.25%)



============================== tracing cpio linux ==============================

2578379 blocks
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 47.77    7.468328           2   2593451           write
 42.33    6.617063           2   2578383           read
  4.50    0.703503           8     79468         6 openat
  2.27    0.355242           4     84591     84591 newfstatat
  1.43    0.223046           2     79455           fchmod
  1.34    0.209322           2     79463           close
  0.23    0.036261           7      5136           mkdir
  0.13    0.020092           3      5136           chmod
  0.00    0.000151          16         9         7 execve
  0.00    0.000082           4        17           mmap
  0.00    0.000030           5         6           mprotect
  0.00    0.000017           2         7           fstat
  0.00    0.000012           6         2           munmap
  0.00    0.000009           2         4           brk
  0.00    0.000007           1         4           pread64
  0.00    0.000005           5         1           chdir
  0.00    0.000005           2         2           set_tid_address
  0.00    0.000005           2         2           set_robust_list
  0.00    0.000004           2         2         2 access
  0.00    0.000004           2         2           arch_prctl
  0.00    0.000004           2         2           prlimit64
  0.00    0.000003           3         1           umask
  0.00    0.000003           1         2           rseq
  0.00    0.000002           2         1           geteuid
  0.00    0.000002           2         1           getrandom
------ ----------- ----------- --------- --------- ----------------
100.00   15.633202           2   5505148     84606 total
2578379 blocks

 Performance counter stats for './asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest':

          3,628.70 msec task-clock:u                     #    0.999 CPUs utilized
                 0      context-switches:u               #    0.000 /sec
                 0      cpu-migrations:u                 #    0.000 /sec
               117      page-faults:u                    #   32.243 /sec
     1,184,610,292      cycles:u                         #    0.326 GHz
       603,041,213      stalled-cycles-frontend:u        #   50.91% frontend cycles idle
     1,299,297,947      instructions:u                   #    1.10  insn per cycle
                                                  #    0.46  stalled cycles per insn
       256,888,594      branches:u                       #   70.794 M/sec
        22,860,064      branch-misses:u                  #    8.90% of all branches

       3.633335330 seconds time elapsed

       0.424213000 seconds user ( 11.74%)
       3.189482000 seconds sys  ( 88.26%)



============================== tracing atv0 linux ==============================

use_copy_file=false
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 49.99    0.770535           9     79429           write
 44.38    0.684102           8     79463           openat
  2.31    0.035663           6      5136           mkdir
  1.70    0.026166          83       315           close_range
  1.62    0.025016        8338         3           munmap
  0.00    0.000003           0         8           close
  0.00    0.000002           0         3           sigaltstack
  0.00    0.000000           0         5           read
  0.00    0.000000           0         4           fstat
  0.00    0.000000           0         1           poll
  0.00    0.000000           0        15           mmap
  0.00    0.000000           0         5           mprotect
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         5           rt_sigaction
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           chdir
  0.00    0.000000           0         1           geteuid
  0.00    0.000000           0         1           getegid
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           chroot
  0.00    0.000000           0         1           sched_getaffinity
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           unshare
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         2           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         3           statx
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ------------------
100.00    1.541487           9    164415         1 total
use_copy_file=false

 Performance counter stats for '/var/home/andrew/Repos/archive-testing/target/release/archive-testing unpack_v0 /tmp/linux.v0 /tmp/dest':

          1,127.08 msec task-clock:u                     #    1.003 CPUs utilized
                 0      context-switches:u               #    0.000 /sec
                 0      cpu-migrations:u                 #    0.000 /sec
                79      page-faults:u                    #   70.093 /sec
        35,213,529      cycles:u                         #    0.031 GHz
        19,637,422      stalled-cycles-frontend:u        #   55.77% frontend cycles idle
        26,758,596      instructions:u                   #    0.76  insn per cycle
                                                  #    0.73  stalled cycles per insn
         8,777,267      branches:u                       #    7.788 M/sec
           582,587      branch-misses:u                  #    6.64% of all branches

       1.123853820 seconds time elapsed

       0.009973000 seconds user (  0.89%)
       1.113715000 seconds sys  ( 99.11%)



============================== tracing atv0cf linux ==============================

use_copy_file=true
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 46.31    0.793785           9     79425           copy_file_range
 39.88    0.683474           8     79463           openat
 11.71    0.200681           2     79463           close
  2.09    0.035826           6      5136           mkdir
  0.01    0.000100          33         3           munmap
  0.00    0.000024           4         5           read
  0.00    0.000018           4         4           write
  0.00    0.000017           3         5           mprotect
  0.00    0.000016          16         1           unshare
  0.00    0.000014           4         3           statx
  0.00    0.000013           2         5           rt_sigaction
  0.00    0.000010           0        15           mmap
  0.00    0.000008           2         3           brk
  0.00    0.000008           2         3           sigaltstack
  0.00    0.000005           5         1           poll
  0.00    0.000004           2         2           prlimit64
  0.00    0.000003           3         1           chdir
  0.00    0.000003           3         1           getegid
  0.00    0.000003           3         1           chroot
  0.00    0.000003           3         1           getrandom
  0.00    0.000002           0         4           fstat
  0.00    0.000002           2         1           lseek
  0.00    0.000002           2         1           geteuid
  0.00    0.000002           2         1           sched_getaffinity
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ------------------
100.00    1.714023           7    243556         1 total
use_copy_file=true

 Performance counter stats for '/var/home/andrew/Repos/archive-testing/target/release/archive-testing unpack_v0 /tmp/linux.v0 /tmp/dest copy_file_range':

          1,128.95 msec task-clock:u                     #    1.003 CPUs utilized
                 0      context-switches:u               #    0.000 /sec
                 0      cpu-migrations:u                 #    0.000 /sec
                80      page-faults:u                    #   70.862 /sec
        35,210,566      cycles:u                         #    0.031 GHz
        18,552,792      stalled-cycles-frontend:u        #   52.69% frontend cycles idle
        23,260,195      instructions:u                   #    0.66  insn per cycle
                                                  #    0.80  stalled cycles per insn
         8,299,573      branches:u                       #    7.352 M/sec
           583,169      branch-misses:u                  #    7.03% of all branches

       1.125577097 seconds time elapsed

       0.011955000 seconds user (  1.06%)
       1.113682000 seconds sys  ( 98.94%)


```

</details>

## discussion

* `atv0`
  * No difference between `write` and `copy_file_range`. This could possibly make a difference if the archive and destination directory are on the same filesystem and that fs supports reflinks. TODO is whether I can use eg btrfs backed only by memory as I want to avoid disk in my use case
  * Hit the target of 99% in sys with the use of `close_range`! Was 98% without `close_range`
  * the time in `munmap` comes from the one unmapping the file, maybe could just not do that if we're gonna exit anyway
  * `close_range` is roughly 10x faster from 0.2 to 0.02 on the linux unpack (see the difference in `write` vs `copy_file_range` b/c I only put it in the `write` version for now. I know this muddies the `copy_file_range` difference but it wasn't significant before (and not sure it ever would be for tmpfs).
    * this might only be suitable for a standalone program, less well behaved in a lib situation I think
      * I am slightly cheating here because the version with `write+close_range` doesn't close the last batch of up to ~250 fds and just exits. would be different in a lib version
* `cpio` is slow! (to be fair this version of the unpacker, not necessarily the format)
  * did 10x more syscalls than `tar`
  * a lot come from the reads and writes in 512 byte increments (!)
* `tar`
  * uses `mkdirat` but seems to do so unconditionally, because it does 18186 with 13050 errors and 18186 - 13050 = 5136 which is the `mkdir` count from the others

Overall good to know for small things like this repo, we can unpack it in less than 1 ms.


# security

Running `scripts/malicious.sh` unpacks an archive which contains directories `../rdir` and `/adir` and files `../rfile` and `/afile`. The `r` is for relative and `a` for absolute. Looking at the strace, we can see that it does not sanitize these paths at all, but they all end up in our destination directory.

```
...
chroot("/tmp/dest")                     = 0
chdir("/")                              = 0
mkdir("../rdir", 0755)                  = 0
mkdir("/adir", 0755)                    = 0
openat(AT_FDCWD, "../rfile", O_WRONLY|O_CREAT, 0755) = 4
close(4)                                = 0
openat(AT_FDCWD, "/afile", O_WRONLY|O_CREAT, 0755) = 4
close(4)                                = 0
...

# ls -l /tmp/dest
total 0
drwxr-xr-x. 2 andrew andrew 40 Sep 20 16:48 adir
-rwxr-xr-x. 1 andrew andrew  0 Sep 20 16:48 afile
drwxr-xr-x. 2 andrew andrew 40 Sep 20 16:48 rdir
-rwxr-xr-x. 1 andrew andrew  0 Sep 20 16:48 rfile
```

This is only preliminary work and not more thoroughly tested yet.

# pack

So everything above is pertaining to unpacking an archive. What about when we want to pack the archive, how can we do so in an efficient manner? Again we only care about directories and regular files, we won't attempt to detect hardlinks (I think) and we won't do any filtering/ignoring, and we will not hit any permission issues (and if we do we'll just ignore them). Just iterate over a dir recursively and make the archive. And the dir will on tmpfs (this has a file name limit of 255 which simplifies using `getdents64`).

## directory listing

Ignoring the archive format v0 layed out above for a moment, one nice approach is a depth first traversal limited to say 32 dirs deep for example. This bounds the number of open fd's because at any time there is one dirfd open at each level in the tree.

syscalls when listing the directory `.`, depth first:


#### `fs::read_dir+debug` (`list_dir`)

glibc

```
statx(AT_FDCWD, ".", AT_STATX_SYNC_AS_STAT, STATX_ALL, {stx_mask=STATX_ALL|STATX_MNT_ID|STATX_SUBVOL, stx_attributes=0, stx_mode=S_IFDIR|0755, stx_size=58, ...}) = 0
openat(AT_FDCWD, ".", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=58, ...}) = 0
getdents64(3, 0x55aa34c05cd0 /* 6 entries */, 32768) = 168
openat(AT_FDCWD, "./src", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=40, ...}) = 0
getdents64(4, 0x55aa34c0de60 /* 5 entries */, 32768) = 144
getdents64(4, 0x55aa34c0de60 /* 0 entries */, 32768) = 0
close(4)                                = 0
openat(AT_FDCWD, "./target", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=80, ...}) = 0
getdents64(4, 0x55aa34c0de60 /* 6 entries */, 32768) = 184
openat(AT_FDCWD, "./target/debug", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 5
fstat(5, {st_mode=S_IFDIR|0755, st_size=204, ...}) = 0
getdents64(5, 0x55aa34c16160 /* 12 entries */, 32768) = 376
openat(AT_FDCWD, "./target/debug/deps", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 6
fstat(6, {st_mode=S_IFDIR|0755, st_size=1764, ...}) = 0
brk(0x55aa34c47000)                     = 0x55aa34c47000
getdents64(6, 0x55aa34c1e2c0 /* 31 entries */, 32768) = 1584
getdents64(6, 0x55aa34c1e2c0 /* 0 entries */, 32768) = 0
close(6)                                = 0
```

musl

```
stat(".", {st_mode=S_IFDIR|0755, st_size=58, ...}) = 0
open(".", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 3
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f527ebb4000
getdents64(3, 0x7f527ebb4048 /* 6 entries */, 2048) = 168
open("./src", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 4
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x7f527ebb4ae8 /* 5 entries */, 2048) = 144
getdents64(4, 0x7f527ebb4ae8 /* 0 entries */, 2048) = 0
close(4)                                = 0
open("./target", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 4
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x7f527ebb5588 /* 7 entries */, 2048) = 232
open("./target/debug", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 5
fcntl(5, F_SETFD, FD_CLOEXEC)           = 0
getdents64(5, 0x7f527ebb4af8 /* 12 entries */, 2048) = 376
open("./target/debug/deps", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 6
fcntl(6, F_SETFD, FD_CLOEXEC)           = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f527ebb2000
getdents64(6, 0x7f527ebb2058 /* 31 entries */, 2048) = 1584
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f527ebb1000
getdents64(6, 0x7f527ebb2058 /* 0 entries */, 2048) = 0
close(6)                                = 0
```

#### `rustix::fs::RawDir+debug` (`list_dir2`)

```
openat(AT_FDCWD, ".", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
getdents64(3, 0x55e85309bcc0 /* 6 entries */, 4096) = 168
openat(3, "src", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4
getdents64(4, 0x55e85309cd60 /* 5 entries */, 4096) = 144
getdents64(4, 0x55e85309cd60 /* 0 entries */, 4096) = 0
fcntl(4, F_GETFD)                       = 0x1 (flags FD_CLOEXEC)
close(4)                                = 0
openat(3, "target", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4
getdents64(4, 0x55e85309de40 /* 7 entries */, 4096) = 232
openat(4, "debug", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x55e85309ee50 /* 12 entries */, 4096) = 376
openat(5, "deps", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 6
getdents64(6, 0x55e85309fe60 /* 31 entries */, 4096) = 1584
getdents64(6, 0x55e85309fe60 /* 0 entries */, 4096) = 0
fcntl(6, F_GETFD)                       = 0x1 (flags FD_CLOEXEC)
close(6)                                = 0
```

```
fcntl(4, F_GETFD)                       = 0x1 (flags FD_CLOEXEC)
 > /usr/lib64/libc.so.6(__fcntl64_nocancel_adjusted+0x27) [0x10eba7]
 > /usr/lib64/libc.so.6(__libc_fcntl64+0x44) [0x109894]
 > /var/home/andrew/Repos/program-explorer/pearchive/target/debug/pearchive(std::sys::pal::unix::fs::debug_assert_fd_is_open+0x28) [0x2cb78]
 > /var/home/andrew/Repos/program-explorer/pearchive/target/debug/pearchive(<std::os::fd::owned::OwnedFd as core::ops::drop::Drop>::drop+0x14) [0x2f934]
 > ...
close(4)                                = 0
```

#### `rustix::fs::RawDir+release`

```
openat(AT_FDCWD, ".", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
getdents64(3, 0x55f847b5aca0 /* 6 entries */, 4096) = 168
openat(3, "src", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4
getdents64(4, 0x55f847b5bd40 /* 5 entries */, 4096) = 144
getdents64(4, 0x55f847b5bd40 /* 0 entries */, 4096) = 0
close(4)                                = 0
openat(3, "target", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4
getdents64(4, 0x55f847b5ce20 /* 7 entries */, 4096) = 232
openat(4, "debug", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x55f847b5de30 /* 12 entries */, 4096) = 376
openat(5, "deps", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 6
getdents64(6, 0x55f847b5ee40 /* 31 entries */, 4096) = 1584
getdents64(6, 0x55f847b5ee40 /* 0 entries */, 4096) = 0
close(6)                                = 0
```

#### hacky `fdopendir` (`list_dir_c`)

musl

```
open(".", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 3
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
fstat(3, {st_mode=S_IFDIR|0755, st_size=88, ...}) = 0
fcntl(3, F_GETFL)                       = 0x18000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1506e20000
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
getdents64(3, 0x7f1506e20048 /* 7 entries */, 2048) = 208
openat(3, "src", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=40, ...}) = 0
fcntl(4, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x7f1506e20ae8 /* 5 entries */, 2048) = 144
getdents64(4, 0x7f1506e20ae8 /* 0 entries */, 2048) = 0
close(4)                                = 0
openat(3, "target", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=130, ...}) = 0
fcntl(4, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x7f1506e21588 /* 7 entries */, 2048) = 232
openat(4, "debug", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 5
fstat(5, {st_mode=S_IFDIR|0755, st_size=204, ...}) = 0
fcntl(5, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(5, F_SETFD, FD_CLOEXEC)           = 0
getdents64(5, 0x7f1506e20af8 /* 12 entries */, 2048) = 376
openat(5, "deps", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 6
fstat(6, {st_mode=S_IFDIR|0755, st_size=2442, ...}) = 0
fcntl(6, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1506e1e000
fcntl(6, F_SETFD, FD_CLOEXEC)           = 0
getdents64(6, 0x7f1506e1e058 /* 39 entries */, 2048) = 2008
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1506e1d000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1506e1c000
getdents64(6, 0x7f1506e1e058 /* 3 entries */, 2048) = 152
getdents64(6, 0x7f1506e1e058 /* 0 entries */, 2048) = 0
close(6)                                = 0
```

glibc

```
openat(AT_FDCWD, ".", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=88, ...}) = 0
fcntl(3, F_GETFL)                       = 0x18000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
getdents64(3, 0x5649ec171d20 /* 7 entries */, 32768) = 208
openat(3, "src", O_RDONLY|O_CLOEXEC|O_DIRECTORY)    = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=40, ...}) = 0
fcntl(4, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x5649ec179df0 /* 5 entries */, 32768) = 144
getdents64(4, 0x5649ec179df0 /* 0 entries */, 32768) = 0
close(4)                                = 0
openat(3, "target", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4
fstat(4, {st_mode=S_IFDIR|0755, st_size=130, ...}) = 0
fcntl(4, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(4, F_SETFD, FD_CLOEXEC)           = 0
getdents64(4, 0x5649ec181f00 /* 7 entries */, 32768) = 232
openat(4, "debug", O_RDONLY|O_CLOEXEC|O_DIRECTORY)  = 5
fstat(5, {st_mode=S_IFDIR|0755, st_size=204, ...}) = 0
fcntl(5, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(5, F_SETFD, FD_CLOEXEC)           = 0
getdents64(5, 0x5649ec189f40 /* 12 entries */, 32768) = 376
openat(5, "deps", O_RDONLY|O_CLOEXEC|O_DIRECTORY)   = 6
fstat(6, {st_mode=S_IFDIR|0755, st_size=2442, ...}) = 0
fcntl(6, F_GETFL)                       = 0x8000 (flags O_RDONLY|O_LARGEFILE|O_DIRECTORY)
fcntl(6, F_SETFD, FD_CLOEXEC)           = 0
brk(0x5649ec1ba000)                     = 0x5649ec1ba000
getdents64(6, 0x5649ec191f80 /* 42 entries */, 32768) = 2160
getdents64(6, 0x5649ec191f80 /* 0 entries */, 32768) = 0
brk(0x5649ec1b2000)                     = 0x5649ec1b2000
close(6)                                = 0
```

### Discussion

* `fs::read_dir` uses a `libc::DIR` under the hood, so we get slightly different results when using glibc vs musl.
  * `opendir` in [glibc](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/opendir.c#L81) calls stat to get the blksize to compute an allocation, though it then uses 32k if it is below that. You can see in smallish dirs (`target/debug/deps` has 29 files for example) that we only get up to `1584`, so not sure where they came up with 32k.
  * `opendir` in [musl](http://git.musl-libc.org/cgit/musl/tree/src/dirent/opendir.c) uses a fixed size `DIR` with a 2k buffer so it's getdents calls are always with 2048. This means it avoids a stat call, but it [does call](http://git.musl-libc.org/cgit/musl/tree/src/fcntl/open.c) `fcntl` with cloexec even though it already passed it in?
  * notice that because there is no `opendirat(DIR, char*)` (except there is a [hidden one in glibc](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/opendir.c#L69), the calls to `open{at}` require us to combine the pathname like `./target/debug/deps` every time, and the kernel has to traverse that path in depth
    * there is an `fdopendir` that I tried using, so I could essentially do `fdopendir(openat(dirfd, "debug"))`, but that is sad because in [musl](http://git.musl-libc.org/cgit/musl/tree/src/dirent/fdopendir.c) it does a `fstat,fcntl(F_SETFD, FD_CLOEXEC)` and [glibc](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/fdopendir.c#L28) also does `fstat,fcntl(F_GETFL),fcntl(F_SETFD, FD_CLOEXEC)`
    * this gets worse if instead of asking it to list `.`, we give it an abs path like `/run/output`, since that prefix now has to appear in every open call (I guess you could chdir but no)
* if we use `getdents64` directly, we can skip all that crap and use `openat` with our dirfd and never concat paths, along with not needing to double check that things are directories or set cloexec because we know we opened with `O_RDONLY|O_DIRECTORY|O_CLOEXEC`
  * notice though that in debug mode there is an `fcntl(F_GETFD)` before close which comes from a debug assert in `OwnedFd`, but in release mode the syscalls look so nice
  * if we do need to concat paths, we can reuse a single buffer, pushing and popping when we enter or leave a directory
* `walkdir` looks identical to `fs::read_dir` in syscalls, though it does print with a leading `./` of the passed in directory so the output doesn't match exactly the others
* see `scripts/testlistdir.sh` that runs everything
* for small dirs we're chasing microseconds but it's been a good investigation

## actually packing now

So let's use `getdents64` directly to walk the input dir, now we need to write things out in a format that is good for packing and unpacking. For that I went the route I alluded to in the beginning about a bytecode. There are 3 types of messages in the v1 pack format, `file name len data`, `dir name`, and `pop`. Names are null terminated so they can be passed directly to `openat` on unpack, len is u32le, and we use a whole byte for the leading tag of `file/dir/pop`. We can write out these messages in depth first order and the unpacker can read them in the same order and execute an appropriate action to create. We maintain a non-empty stack of directory fd's (first entry is our root unpacking directory). The actions are then:

* `file`: create file of `name` in the dirfd at top of stack and write the `data` of `len`
* `dir`: create dir of `name` in the dirfd, open it as an `O_PATH` and push this fd on the stack
* `pop`: close the top of stack and pop it

There is one peephole optimization that we do on unpacking where `dir;pop` is an empty directory and we can skip opening it (since we'd just close it right away). Supporting empty dirs is a potential design choice, but simpler to always write them out. Note that `getdents64` always returns the two entries `.` and `..` and while I think they might always be the first two, I'm not certain that is specified anywhere.

One interesting thing I discovered looking at the strace of the packing was that `File::metadata` uses `statx` when looking up the len of the file (since we need to write it into the output stream first) with `STATX_ALL`. I only need the size and statx lets you pass a mask to tell it what you want, but it looks like the kernel copies the whole thing regardless and a) has to copy more (144 vs 256 byte for `struct stat` vs `struct statx`) and b) does more work in statx; they both call through to `vfs_getattr` but `vfs_statx` does more extra stuff than `vfs_stat`. I imagine that mask is more useful for a fs that isn't assumed tmpfs. So I'm using an fstat. I imagine the difference is in the noise but :shrug:.

Another thing is that rust `io::copy` will first stat both the fd's and then try to do a `copy_file_range` and fallback to `sendfile` if it fails, which it will when the source and destination aren't on the same filesystem, like when copying from `.` (on btrfs in my case) to `/tmp` (on tmpfs). So that is 2 stat's per file and a `copy_file_range` that will fail on every file, so `3N` unnecessary syscalls for our case. So for my use case, I know I'll be writing from tmpfs to pmem which can't use `copy_file_range`, so I switched to using `sendfile` directly and I have to call `fstat` up front to get the file length. Here is a the trace with `io::copy` writing out `.git/description`

```
openat(4, ".git", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x5576b31e2d20 /* 13 entries */, 4096) = 376
openat(5, "description", O_RDONLY|O_CLOEXEC) = 6
fstat(6, {st_mode=S_IFREG|0644, st_size=73, ...}) = 0                                    <- this is us getting the file size
write(3, "\2.git\0\1description\0I\0\0\0", 23) = 23                                      <- writing the "bytecode"
statx(6, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, ...) = 0                    <- io::copy doing statx on infd
statx(3, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, ...) = 0                    <- io::copy doing statx on outfd
copy_file_range(6, NULL, 3, NULL, 1073741824, 0) = -1 EXDEV (Invalid cross-device link)  <- io::copy attempt 1
sendfile(3, 6, NULL, 2147479552)        = 73
sendfile(3, 6, NULL, 2147479552)        = 0
close(6)                                = 0
```

You can also see it [calls sendfile](https://github.com/rust-lang/rust/blob/eeb90cda1969383f56a2637cbd3037bdf598841c/library/std/src/sys/pal/unix/kernel_copy.rs#L228)  with a `max_write` (I think to support streaming fd's) and so it has to follow up with another `sendfile` until it gets a 0! So now we're actually at `4N` syscalls that we can eliminate! Compare that with this trace just using `sendfile` directly:

```
openat(4, ".git", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x555d4437cd20 /* 13 entries */, 4096) = 376
openat(5, "description", O_RDONLY|O_CLOEXEC) = 6
fstat(6, {st_mode=S_IFREG|0644, st_size=73, ...}) = 0
write(3, "\2.git\0\1description\0I\0\0\0", 23) = 23
sendfile(3, 6, NULL, 73)                = 73
close(6)                                = 0
```

Now that looks nice!

On the unpacking side for v1, the trace looks like:

```
...
chroot("/tmp/dest")                     = 0
chdir("/")                              = 0

openat(AT_FDCWD, ".", O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY) = 4
mkdirat(4, ".git", 0755)                = 0
openat(4, ".git", O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY) = 5
openat(5, "description", O_WRONLY|O_CREAT|O_CLOEXEC, 0666) = 6
write(6, "Unnamed repository; edit this fi"..., 73) = 73
close(6)                                = 0
...

mkdirat(4, "empty", 0755)               = 0
openat(4, "readme.md", O_WRONLY|O_CREAT|O_CLOEXEC, 0666) = 5
write(5, "This is a little experiment on f"..., 41994) = 41994
close(5)                                = 0
```

We do the same chroot thing to guard against path traversals, then open our root dirfd (4) and then use `mkdirat` and `openat` to write `.git/description`. Then we see an example of an empty directory called `empty` which we only create, but do not open because we immediately see a `pop` bytecode.

## benchmarking

Initial results are pretty much on par with v0, though I haven't done the `close_range` optimization yet in v1 so I expect them to improve a tad. Though I'm actually not sure I can do that in v1 because we keep directory fd's open and our fd range will be a mix of file and dirs if we do a deferred close. Maybe uring will make an entrance and we can just periodically do a bulk close. Overkill I know.

# io_uring

I wrote an initial io_uring unpacker in `src/ioringv1.rs` called with `unpack_v1_ring` (see `scripts/test0v1.sh` for some initial testing). Wow it's a bit ugly but is correct in my testing so far. There are so many possible variations for implementation strategies for this problem it is a bit overwhelming. I need to stop working on this but I will try to lay out some thoughts I have so far.

The initial implementation only uses io_uring for files because the typical mix will probably have more files than directories. In the simple case, both actually take 3 system calls; for files `openat,write,close`, vs `mkdirat,openat,close`, but `write` might not be complete so might need resubmission.

We have to track some state on the submission queue entry (sqe) because the corresponding completion queue entry (cqe) may not come out in the same order they went in. So we have to attach a `user_data` to distinguish between which file this operation is on and what the operation was. For instance, if a `write` comes back incomplete, we need to look up what file we were writing and get the remainder of the slice to resubmit.

So the overall flow is to queue up `N` files for creation (including writing) and run the batch to completion when it is full. (Another more complicated variant would be to run only once and then continue on, but you can end up with holes in your batch that makes things more complicated). To run a batch, we create a pair of linked sqe's for `openenat+write` (which means our sq needs to be `2N` long) and then submit. Then run over the cq and check a) if the openat errored and b) if the write was incomplete. Incomplete writes need to get resubmitted and update the bookkeeping to track where in the slice we are. Note that in testing against the linux tree 0 files get resubmitted with the max file size of 23MB (`drivers/gpu/drm/amd/include/asic_reg/dcn/dcn_3_2_0_sh_mask.h` what even is that 220k lines of `#define`s!). But I did test this by manually setting the initial write size to be incomplete.

One thing missing is the `close` for the file's `fd`, which is because we use a io_uring direct file table. We size this table to be equal to the batch size. Each entry in the batch uses its natural index into this table. One slightly confusing thing in io_uring is that for `openat` which "creates" an fd, we tell it "hey, open this file and use the slot `i` in our file table" by setting the `file_index` of the op. If you don't set `file_index`, it would create a regular fd that you could use with a standard syscall; direct fd's are not usable outside io_uring. But then when we want to use that direct fd in the write call, the regular `fd` field is set and the op flags are set with `IOSQE_FIXED_FILE`; in the rust wrapper this is taken care of by creating the op like `Write::new(types::Fixed(i))`. Slight asymmetry but okay once you know. We also need to link these two requests so that the `open` happens-before `write`; each pair of ops commutes but within the pair it must be serialized. Okay and so finally to explain the lack of close: let's imagine we're on our second batch so we have some already opened direct fd's in our file table, when we submit a new openat to use index 0 for example, it will close the file at index 0 if one exists. (That happens from `io_openat->io_openat2->io_fixed_fd_install->__io_fixed_fd_install->[io_install_fixed_file](https://elixir.bootlin.com/linux/v6.11/source/io_uring/filetable.c#L80)`). So long story short is we get to skip closing every file fd because it is implicit when we reuse the slot.

One other thing I didn't mention is that we also refcount the dirfd because we can't close it until the files that need it have been cleared out of the batch. Before we were closing the dirfd when it gets popped off the stack since we know we don't need it anymore, but now when we pop there can still be files waiting to be submitted. This means we may use more open fd's than before; where previously we would use up to the max depth in fd's for the dirs, we now might use up to the depth + batch size since in the worst case every file in the batch is under a unique dir and those dirs are at maximum depth. I think that's right.

Looking at the strace summary for unpacking linux with 79455 files and 5139 dirs:

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 98.95   10.121670       32545       311           io_uring_enter
  0.38    0.038684           7      5138           mkdirat
  0.19    0.019904           3      5145           openat
  0.16    0.016000           3      5146           close
  ...
------ ----------- ----------- --------- --------- ------------------
100.00   10.310288         652     15813         1 total
```

we see that we use 15k syscalls to create 79k files (using batch size 256), nice!

On the perf side, things are a bit complicated. For small sizes, there is (unscientifically speaking) no benefit. For large sizes, there can be a benefit, but it only comes when we use multiple cores (for the kernel workers, userspace is still single threaded). For my use case, that isn't very interesting since I'm targeting 1 core or possibly 2 hyperthreads right now. A quick comparison without and with io_uring

```
# without io_uring
# perf stat ./target/release/archive-testing unpack_v1 /tmp/linux.v1 /tmp/dest
       1.144690505 seconds time elapsed

       0.016958000 seconds user
       1.123868000 seconds sys

# with io_uring all cores (16 physical 32 logical)
# perf stat ./target/release/archive-testing unpack_v1_ring /tmp/linux.v1 /tmp/dest
       0.526163889 seconds time elapsed

       0.011397000 seconds user
       7.389336000 seconds sys

# with io_uring 2 cores
# taskset -c 2-3 perf stat ./target/release/archive-testing unpack_v1_ring /tmp/linux.v1 /tmp/dest
       0.929013929 seconds time elapsed

       0.010980000 seconds user
       1.556366000 seconds sys

# with io_uring 1 core
# taskset -c 2 perf stat ./target/release/archive-testing unpack_v1_ring /tmp/linux.v1 /tmp/dest
       1.954103783 seconds time elapsed

       0.014952000 seconds user
       1.924154000 seconds sys
```

So we go from about 2x faster to 2x slower when using all cores vs 1 core. Not amazing.

Just for fun here is small 9 files 3 dirs:

```
# without io_uring
# taskset -c 0 perf stat -r 1000 --pre "bash -c 'rm -rf /tmp/dest && mkdir /tmp/dest'" -- ./target/release/archive-testing unpack_v1 /tmp/archive-testing.v1 /tmp/dest
         0.0001670 +- 0.0000100 seconds time elapsed  ( +-  6.02% )

# with io_uring
# taskset -c 0 perf stat -r 1000 --pre "bash -c 'rm -rf /tmp/dest && mkdir /tmp/dest'" -- ./target/release/archive-testing unpack_v1_ring /tmp/archive-testing.v1 /tmp/dest
        0.00098217 +- 0.00000652 seconds time elapsed  ( +-  0.66% )
```

which has io_uring being about 5x slower, though it's 0.167ms vs 0.982ms. And using more cores doesn't help here.

Maybe there is some tuning with options, I have not fully explored io_uring. And there's also the possibility of not calling into `io_uring_enter` but using the fully async thing, but I doubt that would help that much, we're only doing 311 enters in the linux case (and 1 in the small case!).

# takeaways

I need to focus on other things right now but I'm glad I got some of my io_uring hype out of the way. Overall it's a bit disappointing that unpacking an archive is so slow. For single core, tar vs unpack_v0 vs unpack_v1 vs unpack_v1_ring for linux test case are all in the range of 1.1 - 1.3 seconds, with an archive size of 1.3G, so about 1GB/s, whereas

```
sysbench memory --memory-block-size=1M --memory-total-size=10G run
```

gives me about 40GB/s. Imagine unpacking linux tree in 32ms!
