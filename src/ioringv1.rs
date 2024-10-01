use std::fs::File;
use std::path::Path;
use std::os::fd::{FromRawFd,OwnedFd,IntoRawFd};
use std::io::Write;
use std::ffi::CStr;

use memmap::MmapOptions;
use io_uring::{opcode, types, IoUring};

use crate::common::{Error,read_le_u32,ArchiveFormat1Tag};
use crate::open::{chroot,openpathat,mkdirat,openfile_at,openpath_at_cwd};
//     let read_e = opcode::Read::new(types::Fd(fd.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _)
//         .build()
//         .user_data(0x42);
//
//     // Note that the developer needs to ensure
//     // that the entry pushed into submission queue is valid (e.g. fd, buffer).
//     unsafe {
//         ring.submission()
//             .push(&read_e)
//             .expect("submission queue is full");
//     }
//
//     ring.submit_and_wait(1)?;
//
//     let cqe = ring.completion().next().expect("completion queue is empty");
//
//     assert_eq!(cqe.user_data(), 0x42);
//     assert!(cqe.result() >= 0, "read error: {}", cqe.result());

pub fn unpack_v1_ring(args: &[String]) {
    let inname = args.get(0).ok_or(Error::NoOutfile).unwrap();
    let outname = args.get(1).ok_or(Error::NoOutfile).unwrap();

    let inpath = Path::new(&inname);
    let outpath = Path::new(&outname);
    assert!(inpath.is_file(), "{:?} should be a file", inpath);
    assert!(outpath.is_dir(), "{:?} should be a dir", outpath);

    let infile = File::open(inpath).unwrap();
    let mmap = unsafe { MmapOptions::new().map(&infile).unwrap() };

    chroot(&outpath);

    let mut stack: Vec<OwnedFd> = Vec::with_capacity(32);  // always non-empty
    stack.push(openpath_at_cwd(c".").unwrap());

    let mut cur = &mmap[..];
    loop {
        match cur.get(0).map(|x| x.try_into()) {
            Some(Ok(ArchiveFormat1Tag::File)) => {
                cur = &cur[1..];
                let parent = stack.last().unwrap();
                let name = unsafe { CStr::from_bytes_with_nul_unchecked(cur) };
                let fd = openfile_at(parent, name, libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC).unwrap();
                let mut file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
                let zbi = cur.iter().position(|&x| x == 0).unwrap(); // todo do better
                cur = &cur[zbi+1..];
                let len = read_le_u32(&mut cur) as usize;
                file.write_all(&cur[..len]).unwrap();
                cur = &cur[len..];
            },
            Some(Ok(ArchiveFormat1Tag::Dir)) => {
                cur = &cur[1..];
                let parent = stack.last().unwrap();
                let name = unsafe { CStr::from_bytes_with_nul_unchecked(cur) };
                mkdirat(parent, name).unwrap();
                let zbi = cur.iter().position(|&x| x == 0).unwrap(); // todo do better
                cur = &cur[zbi+1..];
                if *cur.get(0).unwrap() == (ArchiveFormat1Tag::Pop as u8) {
                    // fast path for empty dir, never open the dir and push it
                    cur = &cur[1..];
                } else {
                    let fd = openpathat(parent, name).unwrap();
                    stack.push(fd);
                }
            },
            Some(Ok(ArchiveFormat1Tag::Pop)) => {
                cur = &cur[1..];
                // always expected to be nonempty, todo handle gracefully for malicious archives
                stack.pop().unwrap();
            },
            Some(Err(_)) => {
                let b = cur[0];
                panic!("oh no got bad tag byte {b}");
            },
            None => {
                break;
            }
        }
    }
}
