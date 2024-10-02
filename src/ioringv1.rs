use std::fs::File;
use std::path::Path;
use std::os::fd::{OwnedFd,AsRawFd};
use std::ffi::CStr;
use std::rc::Rc;

use memmap::MmapOptions;
use io_uring::{opcode,types,IoUring};
use io_uring::squeue::Flags;
use io_uring::types::DestinationSlot;

use crate::common::{Error,read_le_u32,ArchiveFormat1Tag};
use crate::open::{chroot,openpath_at_cwd,mkdirat,openpathat};

#[derive(Debug)]
struct Entry<'a> {
    dir_fd: Rc<OwnedFd>,
    name: &'a CStr,
    data: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
enum RingError {
    Push,
    SubmitAndWait,
    DataTooBig,
    Open(i32),
    Write(i32),
    Unk,
}

// runs every request in state until completion doing open, write+, (skips close)
// assumes ring.submission().capacity() == 2 * state.len() so that we can put an open and write
// right away
const NUM_STATES: u64 = 2;
fn run_state(state: &mut Vec<Entry>, ring: &mut IoUring) -> Result<(), RingError> {
    assert!(ring.submission().is_empty());
    for (i, entry) in state.iter().enumerate() {
        let open = opcode::OpenAt::new(types::Fd(entry.dir_fd.as_raw_fd()), entry.name.as_ptr())
            .flags((libc::O_WRONLY | libc::O_CREAT) as _)
            .mode(0o755)
            .file_index(Some(DestinationSlot::try_from_slot_target(i.try_into().unwrap()).unwrap()))
            .build()
            .flags(Flags::IO_LINK)
            .user_data(NUM_STATES*(i as u64));
        let len: u32 = entry.data.len().try_into().map_err(|_| RingError::DataTooBig)?; // todo could be shrunk
        // can use this to force a resubmit of write
        // let len = if len > 100 { len - 100 } else { len };
        let write = opcode::Write::new(types::Fixed(i.try_into().unwrap()), entry.data.as_ptr(), len)
            .offset(u64::MAX)  // == -1 = advance cursor of file
            .build()
            .user_data((NUM_STATES*(i as u64) + 1).try_into().unwrap());
        unsafe {
            ring.submission().push(&open).map_err(|_| RingError::Push)?;
            ring.submission().push(&write).map_err(|_| RingError::Push)?;
        }
    }

    let n = ring.submission().len();
    ring.submit_and_wait(n).map_err(|_| RingError::SubmitAndWait)?;
    let mut remaining: i32 = state.len().try_into().unwrap();
    loop {
        let mut submission = unsafe { ring.submission_shared() };
        let completion = unsafe { ring.completion_shared() };
        assert!(submission.is_empty());
        for cqe in completion {
            let i = cqe.user_data() / NUM_STATES;
            match cqe.user_data() % NUM_STATES {
                0 => {  // this is the open
                    if cqe.result() < 0 { return Err(RingError::Open(cqe.result())); }
                }
                1 => {  // this is a write
                    if cqe.result() < 0 { return Err(RingError::Write(cqe.result())); }
                    let written = cqe.result() as usize; // known positive
                    let entry: &mut Entry = &mut state[i as usize];
                    if written == entry.data.len() { // all done
                        remaining -= 1;
                        // this maybe not even necessary since choosing the same file index should just close it
                        // let close = opcode::Close::new(types::Fixed(i.try_into().unwrap()));
                    } else { // needs resubmission
                        // println!("resubmitting data of size {} written {}", entry.data.len(), written);
                        entry.data = &entry.data[written..];
                        let len = entry.data.len().try_into().map_err(|_| RingError::DataTooBig)?; // todo could be shrunk
                        let write = opcode::Write::new(types::Fixed(i.try_into().unwrap()), entry.data.as_ptr(), len)
                            .offset(u64::MAX)  // == -1 = advance cursor of file
                            .build()
                            .user_data((NUM_STATES*i + 1).try_into().unwrap());
                        unsafe {
                            submission.push(&write).map_err(|_| RingError::Push)?;
                        }
                    }
                }
                _ => { // if we wanted a close, this would be it
                    // this maybe not even necessary since choosing the same file index should just
                    // cause it to be closed ...
                    // if you do do close, then use Close::new(Fixed(i))
                    return Err(RingError::Unk);
                }
            }
        }

        submission.sync();
        let n = submission.len();
        if n == 0 { break; }
        ring.submit_and_wait(n).map_err(|_| RingError::SubmitAndWait)?;
    }
    assert!(remaining == 0);
    state.clear();
    Ok(())
}

// there are loads of ways to use io_uring for our task
// one big decision point is whether to use regular or direct fd's
//   - note that openat always takes a regular fd for the directory fd arg so we can only ever
//     openat a dir into a regular fd anyways
//   - that doesn't mean we can't use uring for the opendir, but it presents a big challenge since
//     we need the result of that open for subsequent opens, so you have to submit anyways
// so a simple approach is to only use it for writes to files, since those take an open,write+,close
// making a dir does mkdirat,openat,close but we have to have those fd's avaiable for all the
// openats, so the ordering isn't so easy
// plus for the linux example, there are 5139 dirs and 79455 files so start with the bigger thing
#[allow(unused_variables)]
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

    let mut stack: Vec<Rc<OwnedFd>> = Vec::with_capacity(32);  // always non-empty
    stack.push(openpath_at_cwd(c".").unwrap().into());

    let batch_size: usize = 256;
    let mut ring = IoUring::new((2 * batch_size).try_into().unwrap()).unwrap();
    let mut state: Vec<Entry> = Vec::with_capacity(batch_size);

    // I don't think there's a difference for us for this
    ring.submitter().register_files_sparse(batch_size.try_into().unwrap()).unwrap();
    // let fds: [i32; 256] = [-1; 256];
    // ring.submitter().register_files(&fds).unwrap();

    let mut cur = &mmap[..];
    loop {
        match cur.get(0).map(|x| x.try_into()) {
            Some(Ok(ArchiveFormat1Tag::File)) => {
                cur = &cur[1..];
                let parent = stack.last().unwrap();
                let name = unsafe { CStr::from_bytes_with_nul_unchecked(cur) };
                let zbi = cur.iter().position(|&x| x == 0).unwrap(); // todo do better
                cur = &cur[zbi+1..];
                let len = read_le_u32(&mut cur) as usize;
                let data = &cur[..len];
                state.push(Entry { dir_fd: parent.clone(), name: name, data: data });
                if state.len() == batch_size {
                    run_state(&mut state, &mut ring).unwrap();
                }
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
                    stack.push(fd.into());
                }
            },
            Some(Ok(ArchiveFormat1Tag::Pop)) => {
                cur = &cur[1..];
                // always expected to be nonempty, todo handle gracefully for malicious archives
                stack.pop().unwrap();
                // TODO this calls close(2) directly (once the rc count is dropped) and doesn't
                // actully use io_uring ...
            },
            Some(Err(_)) => {
                let b = cur[0];
                panic!("oh no got bad tag byte {b}");
            },
            None => {
                run_state(&mut state, &mut ring).unwrap();
                break;
            }
        }
    }
}
