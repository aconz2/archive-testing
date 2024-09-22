use std::env;
use std::collections::HashSet;
use std::path::Path;
use std::io;
use std::io::{stdin,BufRead,Write,BufWriter,Seek,SeekFrom};
use std::ffi::OsString;
use std::os::unix::prelude::OsStrExt;
use std::os::fd::{FromRawFd,AsRawFd,IntoRawFd};
use std::fs::File;
use memmap::MmapOptions;
use std::os::unix::fs;
use std::ptr;

// default fd table size is 64, we 3 + 1 open by default but we don't want to go to fd 257 because
// that would trigger a realloc and then we waste, so this should always be 4 less than a power of
// 2. Seems like diminishing returns
const CLOSE_EVERY: i32 = 256 - 4;

#[derive(Debug)]
enum Error {
    NoOutfile,
    CopyFileRange,
    Align,
}

fn join_bytes<'a, I: Iterator<Item = &'a [u8]>>(xs: I) -> Vec<u8> {
    let mut acc: Vec<u8> = vec![];
    for x in xs {
        acc.extend_from_slice(x);
        acc.push(0)
    }
    acc
}

// really just writing this to support cpio to avoid --make-directories
fn list_dirs(_args: &[String]) {
    let files = {
        let mut acc: Vec<_> = stdin().lock().lines().map(|x| x.unwrap()).collect();
        acc.sort();
        acc
    };
    let dirs = {
        let mut acc = HashSet::new();
        let empty = OsString::new();
        for file in &files {
            let p = Path::new(&file);
            if !p.is_file() { continue; }
            assert!(p.is_file(), "{:?} is not file", p);
            for parent in p.ancestors().skip(1) {
                if parent != empty {
                    acc.insert(parent.to_owned());
                }
            }
        }
        let mut acc: Vec<_> = acc.drain().collect();
        acc.sort();
        acc
    };
    for dir in dirs {
        println!("{}", dir.into_os_string().into_string().unwrap());
    }
}

fn align_to_4<W: Seek + Write>(writer: &mut W) -> Result<(), Error> {
    let pos = writer.stream_position().map_err(|_| Error::Align)?;
    let adj = 4 - (pos % 4);
    for _ in 0..adj { writer.write(&[0]).map_err(|_| Error::Align)?; }
    let pos = writer.stream_position().map_err(|_| Error::Align)?;
    //println!("wrote {} bytes of padding, pos now {}", adj, pos);
    assert!(pos % 4 == 0);
    Ok(())
}

fn make_malicious_archive(args: &[String]) {
    let outname = args.get(0).ok_or(Error::NoOutfile).unwrap();
    let outfile = File::create(outname).unwrap();
    let mut outwriter = BufWriter::new(outfile);
    let dirsb = b"../rdir\0/adir\0";
    let filesb = b"../rfile\0/afile\0";
    for i in vec![2, 2, dirsb.len(), filesb.len()] {
        outwriter.write(&(i as u32).to_le_bytes()).unwrap();
    }
    outwriter.write(&dirsb[..]).unwrap();
    outwriter.write(&filesb[..]).unwrap();
    align_to_4(&mut outwriter).unwrap();
    for size in vec![0, 0] {
        outwriter.write(&(size as u32).to_le_bytes()).unwrap();
    }
}

/// v0 archive format
/// num_dirs: u32le 
/// num_files: u32le
/// dirnames_size: u32le
/// filenames_size: u32le
/// <dirnames with null bytes> of length dirnames_size bytes
/// <filenames with null bytes> of length filenames_size bytes
/// 0-3 padding bytes to align file_sizes up to 4 byte alignment
/// <num_files x u32le file sizes> of length num_files * 4 bytes
/// <data>
/// ---
/// input is line separated pathnames relative to cwd
/// ---
/// args <output file>
fn create_v0(args: &[String]) {
    let outname = args.get(0).ok_or(Error::NoOutfile).unwrap();
    let outfile = File::create(outname).unwrap();
    let mut outwriter = BufWriter::new(outfile);
    let files = {
        let mut acc: Vec<_> = stdin().lock().lines().map(|x| x.unwrap()).collect();
        acc.sort();
        acc
    };
    let mut sizes = vec![];
    let mut size = 0;
    let dirs = {
        let mut acc = HashSet::new();
        let empty = OsString::new();
        for file in &files {
            let p = Path::new(&file);
            if !p.is_file() { continue; }
            let file_len = p.metadata().unwrap().len();
            sizes.push(file_len);
            size += file_len;
            assert!(p.is_file(), "{:?} is not file", p);
            for parent in p.ancestors().skip(1) {
                if parent != empty {
                    acc.insert(parent.to_owned());
                }
            }
        }
        let mut acc: Vec<_> = acc.drain().collect();
        acc.sort();
        acc
    };
    let filesb = join_bytes(files.iter().map(|x| x.as_bytes()));
    let dirsb = join_bytes(dirs.iter().map(|x| x.as_os_str().as_bytes()));
    println!("there are {} dirs", dirs.len());
    println!("there are {} files", files.len());
    println!("total bytes of data {}", size);
    println!("filenames len {}", filesb.len());
    println!("writing to {}", outname);
    println!("dirsb len {}", dirsb.len());
    for i in vec![dirs.len(), files.len(), dirsb.len(), filesb.len()] {
        outwriter.write(&(i as u32).to_le_bytes()).unwrap();
    }
    outwriter.write(&dirsb).unwrap();
    outwriter.write(&filesb).unwrap();
    align_to_4(&mut outwriter).unwrap();

    for size in sizes {
        outwriter.write(&(size as u32).to_le_bytes()).unwrap();
    }
    for file in &files {
        let mut f = File::open(file).unwrap();
        io::copy(&mut f, &mut outwriter).unwrap();
    }
}

fn chroot(dir: &Path) {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    unsafe {
        let ret = libc::unshare(libc::CLONE_NEWUSER);
        assert!(ret == 0, "unshare fail");
    }
    File::create("/proc/self/uid_map").unwrap()
        .write_all(format!("0 {} 1", uid).as_bytes()).unwrap();
    File::create("/proc/self/setgroups").unwrap().write_all(b"deny").unwrap();
    File::create("/proc/self/gid_map").unwrap()
        .write_all(format!("0 {} 1", gid).as_bytes()).unwrap();
    fs::chroot(dir).unwrap();
    std::env::set_current_dir("/").unwrap();
}

fn as_slice<T>(data: &[u8]) -> Option<&[T]> {
    let len = data.len();
    let ptr = data.as_ptr();
    let align = std::mem::align_of::<T>();
    if len % align != 0 { return None; }
    if (ptr as usize) % align != 0 { return None; }
    unsafe {
        let ptr = ptr as *const T;
        Some(std::slice::from_raw_parts(ptr, len / align))
    }
}

fn copy_file_range_all(filein: &mut File, fileout: &mut File, len: usize) -> Result<(), Error> {
    let fd_in  = filein.as_raw_fd();
    let fd_out = fileout.as_raw_fd();
    let mut len = len;
    while len > 0 {
        let ret = unsafe {
            libc::copy_file_range(fd_in, ptr::null_mut(), fd_out, ptr::null_mut(), len, 0)
        };
        if ret < 0 { return Err(Error::CopyFileRange); }
        if ret == 0 { return Err(Error::CopyFileRange); }
        let ret = ret as usize;
        if ret > len { return Err(Error::CopyFileRange); }
        len -= ret;
    }
    Ok(())
}

/// args <infile> <output dir> 
///   <output dir> should be empty
fn unpack_v0(args: &[String]) {
    let inname = args.get(0).ok_or(Error::NoOutfile).unwrap();
    let outname = args.get(1).ok_or(Error::NoOutfile).unwrap();
    let use_copy_file = { 
        if let Some(s) = args.get(2) {
            s == "copy_file_range"
        } else {
            false
        }
    };
    println!("use_copy_file={}", use_copy_file);
    let inpath = Path::new(&inname);
    let outpath = Path::new(&outname);
    assert!(inpath.is_file(), "{:?} should be a file", inpath);
    assert!(outpath.is_dir(), "{:?} should be a dir", outpath);
    let mut infile = File::open(inpath).unwrap();
    let mmap = unsafe { MmapOptions::new().map(&infile).unwrap() };
    let (num_dirs, num_files, dirnames_size, filenames_size) = {
        (
            u32::from_le_bytes(mmap[0..4].try_into().unwrap()) as usize,
            u32::from_le_bytes(mmap[4..8].try_into().unwrap()) as usize,
            u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize,
            u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as usize,
        )
    };
    let dirnames_start = 4 * 4;
    let filenames_start = dirnames_start + dirnames_size;
    let filesizes_start = {
        let mut x = filenames_start + filenames_size;
        if x % 4 != 0 {
            let adj = 4 - (x % 4);
            x += adj;
        }
        x
    };
    assert!(filesizes_start % 4 == 0, "filesizes_start={}", filesizes_start);
    let data_start = filesizes_start + (4 * num_files);

    chroot(&outpath);

    {
        let mut dirnames_cur = &mmap[dirnames_start..filenames_start];
        for _ in 0..num_dirs {
            unsafe {
                let ret = libc::mkdir(dirnames_cur.as_ptr() as *const i8, 0o755);
                assert!(ret == 0, "mkdir failed");
            }
            // idk is it better to do dirnames_buf.split(0)? 
            let zbi = dirnames_cur.iter().position(|&x| x == 0).unwrap();
            dirnames_cur = &dirnames_cur[zbi+1..];
        }
    }

    // kinda ugly
    if use_copy_file {
        let mut filenames_cur = &mmap[filenames_start..filesizes_start];
        let filesizes = as_slice::<u32>(&mmap[filesizes_start..data_start]).unwrap();
        assert!(filesizes.len() == num_files);
        infile.seek(SeekFrom::Start(data_start as u64)).unwrap();
        for size in filesizes {
            let size = *size as usize;
            let mut fileout = unsafe {
                let fd = libc::open(filenames_cur.as_ptr() as *const i8, libc::O_CREAT | libc::O_WRONLY, 0o755);
                assert!(fd > 0, "open failed");
                File::from_raw_fd(fd)
            };
            copy_file_range_all(&mut infile, &mut fileout, size).unwrap();
            let zbi = filenames_cur.iter().position(|&x| x == 0).unwrap();
            filenames_cur = &filenames_cur[zbi+1..];
        };

    } else {
        let mut filenames_cur = &mmap[filenames_start..filesizes_start];
        let filesizes = as_slice::<u32>(&mmap[filesizes_start..data_start]).unwrap();
        assert!(filesizes.len() == num_files);
        let mut data_cur = &mmap[data_start..];

        let mut close_every: i32 = CLOSE_EVERY;

        for size in filesizes {
            let size = *size as usize;
            let mut fileout = unsafe {
                let fd = libc::open(filenames_cur.as_ptr() as *const i8, libc::O_CREAT | libc::O_WRONLY, 0o755);
                assert!(fd > 0, "open failed");
                File::from_raw_fd(fd)
            };
            let data = &data_cur[..size];
            assert!(data.len() == size);
            fileout.write_all(data).unwrap();
            data_cur = &data_cur[size..];

            let _ = fileout.into_raw_fd();
            close_every -= 1;
            if close_every == 0 {
                unsafe {
                    // TODO if this was in a lib we'd want to figure out our current fd that we'll
                    // go into and/or verify there aren't any random fds above us but not sure you
                    // can do that well so maybe this is only a go if we're a standalone exe
                    libc::close_range(4, std::u32::MAX, 0);
                }
                close_every = CLOSE_EVERY;
            }

            let zbi = filenames_cur.iter().position(|&x| x == 0).unwrap();
            filenames_cur = &filenames_cur[zbi+1..];
        }
    }

    // TODO if this was in a lib we'd want to do another libc::close_range(4, std::u32::MAX, 0)
    // here
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("create_v0") => { create_v0(&args[2..]); },
        Some("unpack_v0") => { unpack_v0(&args[2..]); },
        Some("list_dirs") => { list_dirs(&args[2..]); },
        Some("make_malicious") => { make_malicious_archive(&args[2..]); },
        _ => {
            println!("create_v0 <output-file> < <file-list>");
            println!("unpack_v0 <input-file> <output-file> [copy_file_range]");
            println!("list_dirs < <file-list>");
        }
    }
}
