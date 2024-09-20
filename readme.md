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

Okay to benchmark we'll test a small dir, this repo, and a big dir, the linux 6.2 tree. We'll test a `write` version of this unpacker and a `copy_file_range`. We want to look at time and also syscall counts. The destination directory will be on tmpfs and so will the archives. I want to test tar and cpio, no compression, and filtering out any links. I've created the cpio arhive with all the directories up front just like this archiver to give a more fair comparison. If you only give it a list of files, it won't create the directories unless you also pass the `--make-directories`.

Note that I added a small patch to `perf` to give the user/sys breakdown with percentages. Tbd if I can figure out how to submit it.

And if you read the test script, you'll see I am using a wrapper `src/asstdin.c` to redirect stdin so we don't have to use the shell with hyperfine for cpio.

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

Here are the results from `./scripts/test.sh`. This is only testing the extraction process. `atv0` is using `write` and `atv0cf` is using `copy_file_range` to write the file contents. That acronym is `archive-testing-v0` (though I haven't tested any other version yet).

<details>

<summary>full results</summary>

```
============================== hyperfine archive-testing ==============================

Benchmark 1: tar
  Time (mean ± σ):       1.0 ms ±   0.0 ms    [User: 0.2 ms, System: 0.8 ms]
  Range (min … max):     1.0 ms …   1.2 ms    879 runs
 
Benchmark 2: cpio
  Time (mean ± σ):     967.4 µs ±  51.1 µs    [User: 175.3 µs, System: 724.6 µs]
  Range (min … max):   891.0 µs … 1304.2 µs    1023 runs
 
Benchmark 3: atv0
  Time (mean ± σ):     558.0 µs ±  33.8 µs    [User: 262.2 µs, System: 232.9 µs]
  Range (min … max):   518.3 µs … 831.1 µs    1170 runs
 
  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.
 
Benchmark 4: atv0cf
  Time (mean ± σ):     554.6 µs ±  27.4 µs    [User: 276.1 µs, System: 218.3 µs]
  Range (min … max):   518.8 µs … 689.2 µs    1214 runs
 
  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs.
 
Summary
  atv0cf ran
    1.01 ± 0.08 times faster than atv0
    1.74 ± 0.13 times faster than cpio
    1.86 ± 0.11 times faster than tar

============================== hyperfine linux ==============================

Benchmark 1: tar
  Time (mean ± σ):      1.396 s ±  0.035 s    [User: 0.097 s, System: 1.287 s]
  Range (min … max):    1.365 s …  1.484 s    10 runs
 
Benchmark 2: cpio
  Time (mean ± σ):      3.631 s ±  0.014 s    [User: 0.438 s, System: 3.168 s]
  Range (min … max):    3.612 s …  3.655 s    10 runs
 
Benchmark 3: atv0
  Time (mean ± σ):      1.100 s ±  0.006 s    [User: 0.020 s, System: 1.076 s]
  Range (min … max):    1.092 s …  1.110 s    10 runs
 
Benchmark 4: atv0cf
  Time (mean ± σ):      1.105 s ±  0.005 s    [User: 0.017 s, System: 1.083 s]
  Range (min … max):    1.098 s …  1.114 s    10 runs
 
Summary
  atv0 ran
    1.00 ± 0.01 times faster than atv0cf
    1.27 ± 0.03 times faster than tar
    3.30 ± 0.02 times faster than cpio

============================== tracing tar linux ==============================

% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 37.44    0.969450           4    205097           write
 26.25    0.679687           8     83952      4482 openat
 17.94    0.464465           3    133658           read
  8.06    0.208806           2     79455           utimensat
  7.48    0.193614           2     79471           close
  2.83    0.073334           4     18186     13050 mkdirat
  0.00    0.000045           2        18           newfstatat
  0.00    0.000007           2         3           fcntl
  0.00    0.000006           0        28           mmap
  0.00    0.000006           2         3         1 statfs
  0.00    0.000005           2         2           lseek
  0.00    0.000005           2         2           umask
  0.00    0.000004           2         2         1 access
  0.00    0.000003           3         1           rt_sigaction
  0.00    0.000002           2         1           geteuid
  0.00    0.000000           0         7           mprotect
  0.00    0.000000           0         1           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         2         1 arch_prctl
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ----------------
100.00    2.589439           4    599900     17535 total

 Performance counter stats for 'tar --extract --file /tmp/linux.tar --directory /tmp/dest':

          1,491.31 msec task-clock:u                     #    1.001 CPUs utilized             
                 0      context-switches:u               #    0.000 /sec                      
                 0      cpu-migrations:u                 #    0.000 /sec                      
               119      page-faults:u                    #   79.796 /sec                      
       342,836,621      cycles:u                         #    0.230 GHz                         (83.36%)
         1,505,710      stalled-cycles-frontend:u        #    0.44% frontend cycles idle        (83.27%)
         7,348,746      stalled-cycles-backend:u         #    2.14% backend cycles idle         (83.32%)
       488,311,286      instructions:u                   #    1.42  insn per cycle            
                                                  #    0.02  stalled cycles per insn     (83.36%)
        95,864,671      branches:u                       #   64.282 M/sec                       (83.34%)
         2,889,751      branch-misses:u                  #    3.01% of all branches             (83.36%)

       1.489120269 seconds time elapsed

       0.089101000 seconds user (  6.56%)
       1.268913000 seconds sys  ( 93.44%)



============================== tracing cpio linux ==============================

2578379 blocks
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 45.62    6.884368           2   2593451           write
 44.71    6.747062           2   2578383           read
  4.32    0.652502           8     79468         6 openat
  2.27    0.343033           4     84598     84591 newfstatat
  1.41    0.212957           2     79455           fchmod
  1.31    0.198007           2     79463           close
  0.23    0.034311           6      5136           mkdir
  0.13    0.019090           3      5136           chmod
  0.00    0.000427          42        10         8 execve
  0.00    0.000089           5        17           mmap
  0.00    0.000031           5         6           mprotect
  0.00    0.000014           7         2           munmap
  0.00    0.000013           3         4           pread64
  0.00    0.000011           2         4           brk
  0.00    0.000011           2         4         2 arch_prctl
  0.00    0.000008           4         2         2 access
  0.00    0.000005           2         2           set_robust_list
  0.00    0.000005           2         2           rseq
  0.00    0.000004           4         1           chdir
  0.00    0.000004           2         2           set_tid_address
  0.00    0.000004           2         2           prlimit64
  0.00    0.000003           3         1           umask
  0.00    0.000003           3         1           getrandom
  0.00    0.000002           2         1           geteuid
------ ----------- ----------- --------- --------- ----------------
100.00   15.091964           2   5505151     84609 total
2578379 blocks

 Performance counter stats for './asstdin /tmp/linux.cpio cpio --extract --directory /tmp/dest':

          3,945.63 msec task-clock:u                     #    0.991 CPUs utilized             
                 0      context-switches:u               #    0.000 /sec                      
                 0      cpu-migrations:u                 #    0.000 /sec                      
               121      page-faults:u                    #   30.667 /sec                      
     1,103,608,241      cycles:u                         #    0.280 GHz                         (83.44%)
        10,324,259      stalled-cycles-frontend:u        #    0.94% frontend cycles idle        (83.22%)
        17,399,458      stalled-cycles-backend:u         #    1.58% backend cycles idle         (83.46%)
     1,291,626,189      instructions:u                   #    1.17  insn per cycle            
                                                  #    0.01  stalled cycles per insn     (83.22%)
       258,485,271      branches:u                       #   65.512 M/sec                       (83.43%)
        22,740,295      branch-misses:u                  #    8.80% of all branches             (83.22%)

       3.981683568 seconds time elapsed

       0.421381000 seconds user ( 11.75%)
       3.164663000 seconds sys  ( 88.25%)



============================== tracing atv0 linux ==============================

use_copy_file=false
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 45.12    0.742110           9     79429           write
 39.30    0.646434           8     79463           openat
 11.95    0.196590           2     79463           close
  2.06    0.033806           6      5136           mkdir
  1.57    0.025774        8591         3           munmap
  0.00    0.000023           4         5           read
  0.00    0.000018          18         1           unshare
  0.00    0.000012           4         3           statx
  0.00    0.000011           0        15           mmap
  0.00    0.000011           2         5           rt_sigaction
  0.00    0.000009           3         3           brk
  0.00    0.000008           2         3           sigaltstack
  0.00    0.000005           1         5           mprotect
  0.00    0.000004           4         1           poll
  0.00    0.000004           4         1           chroot
  0.00    0.000004           4         1           sched_getaffinity
  0.00    0.000003           3         1           chdir
  0.00    0.000003           3         1           getrandom
  0.00    0.000002           2         1           geteuid
  0.00    0.000002           2         1           getegid
  0.00    0.000002           0         4           newfstatat
  0.00    0.000002           1         2           prlimit64
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         2         1 arch_prctl
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ------------------
100.00    1.644837           6    243556         2 total
use_copy_file=false

 Performance counter stats for '/var/home/andrew/Repos/archive-testing/target/release/archive-testing unpack_v0 /tmp/linux.v0 /tmp/dest':

          1,195.37 msec task-clock:u                     #    1.002 CPUs utilized             
                 0      context-switches:u               #    0.000 /sec                      
                 0      cpu-migrations:u                 #    0.000 /sec                      
                81      page-faults:u                    #   67.761 /sec                      
        47,702,960      cycles:u                         #    0.040 GHz                         (83.29%)
            69,364      stalled-cycles-frontend:u        #    0.15% frontend cycles idle        (83.25%)
         4,339,727      stalled-cycles-backend:u         #    9.10% backend cycles idle         (83.38%)
        27,524,784      instructions:u                   #    0.58  insn per cycle            
                                                  #    0.16  stalled cycles per insn     (83.39%)
         9,121,462      branches:u                       #    7.631 M/sec                       (83.34%)
           816,019      branch-misses:u                  #    8.95% of all branches             (83.35%)

       1.193302957 seconds time elapsed

       0.019090000 seconds user (  1.75%)
       1.070128000 seconds sys  ( 98.25%)



============================== tracing atv0cf linux ==============================

use_copy_file=true
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ------------------
 47.45    0.770331           9     79425           copy_file_range
 38.94    0.632160           7     79463           openat
 11.57    0.187775           2     79463           close
  2.03    0.033009           6      5136           mkdir
  0.01    0.000094          31         3           munmap
  0.00    0.000080           5        15           mmap
  0.00    0.000030           6         5           read
  0.00    0.000024           4         5           mprotect
  0.00    0.000018           4         4           write
  0.00    0.000015          15         1           unshare
  0.00    0.000014           4         3           statx
  0.00    0.000012           2         5           rt_sigaction
  0.00    0.000011           2         4           newfstatat
  0.00    0.000008           2         3           sigaltstack
  0.00    0.000007           2         3           brk
  0.00    0.000005           2         2           prlimit64
  0.00    0.000004           2         2           pread64
  0.00    0.000004           4         1           chroot
  0.00    0.000004           4         1           sched_getaffinity
  0.00    0.000003           3         1           poll
  0.00    0.000003           3         1           chdir
  0.00    0.000003           3         1           geteuid
  0.00    0.000003           1         2         1 arch_prctl
  0.00    0.000003           3         1           set_robust_list
  0.00    0.000003           3         1           getrandom
  0.00    0.000002           2         1           lseek
  0.00    0.000001           1         1           getegid
  0.00    0.000001           1         1           set_tid_address
  0.00    0.000001           1         1           rseq
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
------ ----------- ----------- --------- --------- ------------------
100.00    1.623628           6    243557         2 total
use_copy_file=true

 Performance counter stats for '/var/home/andrew/Repos/archive-testing/target/release/archive-testing unpack_v0 /tmp/linux.v0 /tmp/dest copy_file_range':

          1,190.43 msec task-clock:u                     #    1.002 CPUs utilized             
                 0      context-switches:u               #    0.000 /sec                      
                 0      cpu-migrations:u                 #    0.000 /sec                      
                81      page-faults:u                    #   68.043 /sec                      
        31,901,523      cycles:u                         #    0.027 GHz                         (83.28%)
            23,167      stalled-cycles-frontend:u        #    0.07% frontend cycles idle        (83.25%)
         1,835,911      stalled-cycles-backend:u         #    5.75% backend cycles idle         (83.36%)
        23,431,675      instructions:u                   #    0.73  insn per cycle            
                                                  #    0.08  stalled cycles per insn     (83.39%)
         8,284,905      branches:u                       #    6.960 M/sec                       (83.39%)
           581,706      branch-misses:u                  #    7.02% of all branches             (83.33%)

       1.187922685 seconds time elapsed

       0.014561000 seconds user (  1.34%)
       1.070352000 seconds sys  ( 98.66%)


```

</details>

## discussion

* `atv0`
  * No difference between `write` and `copy_file_range`. This could possibly make a difference if the archive and destination directory are on the same filesystem and that fs supports reflinks. TODO is whether I can use eg btrfs backed only by memory as I want to avoid disk in my use case
  * Almost hit the target of 99% in sys, at 98%
  * the time in `munmap` comes from the one unmapping the file, maybe could just not do that if we're gonna exit anyway
* `cpio` is slow!
  * did 10x more syscalls than `tar`
  * a lot come from the reads and writes in 512 byte increments (!)
* `tar`
  * uses `mkdirat` but seems to do so unconditionally, because it does 18186 with 13050 errors and 18186 - 13050 = 5136 which is the `mkdir` count from the others

Overall good to know for small things like this repo, we can unpack it in less than 1 ms.

