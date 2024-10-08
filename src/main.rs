use std::collections::HashSet;
use std::env;
use std::ffi::CStr;
use std::ffi::OsString;
use std::fs::File;
use std::io::{stdin,BufRead,Write,BufWriter,Seek,SeekFrom};
use std::io;
use std::os::fd::{FromRawFd,AsRawFd,IntoRawFd,OwnedFd};
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::ptr;

use memmap::MmapOptions;

mod common;
mod open;
mod liblistdir;
mod ioringv1;

use liblistdir::{Visitor,list_dir};
use open::{mkdirat,openpathat,chroot,openpath_at_cwd,openfile_at};
use common::{Error,read_le_u32,ArchiveFormat1Tag};
use ioringv1::unpack_v1_ring;

// default fd table size is 64, we 3 + 1 open by default but we don't want to go to fd 257 because
// that would trigger a realloc and then we waste, so this should always be 4 less than a power of
// 2. Seems like diminishing returns
const CLOSE_EVERY: i32 = 256 - 4;

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
    if pos % 4 == 0 { return Ok(()); }
    let adj = 4 - (pos % 4);
    for _ in 0..adj { writer.write_all(&[0]).map_err(|_| Error::Align)?; }
    let pos = writer.stream_position().map_err(|_| Error::Align)?;
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
        outwriter.write_all(&(i as u32).to_le_bytes()).unwrap();
    }
    outwriter.write_all(&dirsb[..]).unwrap();
    outwriter.write_all(&filesb[..]).unwrap();
    align_to_4(&mut outwriter).unwrap();
    for size in vec![0, 0] {
        outwriter.write_all(&(size as u32).to_le_bytes()).unwrap();
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
fn pack_v0(args: &[String]) {
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
        outwriter.write_all(&(i as u32).to_le_bytes()).unwrap();
    }
    outwriter.write_all(&dirsb).unwrap();
    outwriter.write_all(&filesb).unwrap();
    align_to_4(&mut outwriter).unwrap();

    {
        let filesizes_start = outwriter.stream_position().unwrap();
        println!("filesizes_start={filesizes_start}");
    }
    for size in sizes {
        outwriter.write_all(&(size as u32).to_le_bytes()).unwrap();
    }
    for file in &files {
        let mut f = File::open(file).unwrap();
        io::copy(&mut f, &mut outwriter).unwrap();
    }
}

/// v1 archive format
/// message+
/// message =
///   | file: <tag> <name zero term> <u32le> <blob>
///   | dir:  <tag> <name zero term>
///   | pop:  <tag>
///
/// alternate format would be to buffer the names and sizes and just dump
/// the blob data so, this avoids the write per message but requires buffering
/// <blob size> <blob data> <message+>
/// message =
///   | file: <tag> <name zero term> <u32le>
///   | dir:  <tag> <name zero term>
///   | pop:  <tag>
///
/// on the decode side, we'll probably mmap it so not much different


// So i intended to have this generic over a writer so you could eg test with a vec, but then idk
// how to do the specialization for files when we want to use sendfile; I think io::copy does this
// appropriately but the 99% case is for files, so just do that
// struct MyVisitor<W: Write> {
//     writer: BufWriter::<W>,
// }
//
// impl<W: Write> MyVisitor<W> {
//     fn new(out: W) -> MyVisitor<W> {
//         MyVisitor { writer: BufWriter::<W>::new(out), }
//     }
//
//     fn into_writer(self) -> W {
//         self.writer.into_inner().map_err(|_| Error::Write).unwrap()
//     }
// }

struct MyVisitor {
    writer: BufWriter::<File>,
}

impl MyVisitor {
    fn new(out: File) -> MyVisitor {
        MyVisitor { writer: BufWriter::new(out) }
    }

    fn into_file(self) -> File {
        self.writer.into_inner().map_err(|_| Error::Write).unwrap()
    }
}

// the File::metadata.len() uses statx with STATX_ALL
// the statx struct is much bigger than stat and even with masking
// it still does a copy of the whole thing
#[allow(dead_code)]
fn file_size_statx<Fd: AsRawFd>(fd: &Fd) -> Result<u64, Error> {
    use std::mem;
    let size = unsafe {
        let empty_path = c"";
        let mut buf: libc::statx = mem::zeroed();
        let ret = libc::statx(
            fd.as_raw_fd(), empty_path.as_ptr(),
            libc::AT_STATX_SYNC_AS_STAT | libc::AT_EMPTY_PATH,
            libc::STATX_SIZE,
            &mut buf as *mut _
        );
        if ret < 0 { return Err(Error::Statx); }
        buf.stx_size
    };
    Ok(size)
}

fn file_size_fstat<Fd: AsRawFd>(fd: &Fd) -> Result<u64, Error> {
    use std::mem;
    let size = unsafe {
        let mut buf: libc::stat = mem::zeroed();
        let ret = libc::fstat(
            fd.as_raw_fd(),
            &mut buf as *mut _
        );
        if ret < 0 { return Err(Error::Fstat); }
        buf.st_size
    };
    // dude st_size is signed here and unsigned in statx
    size.try_into().map_err(|_| Error::Fstat)
}

fn file_size<Fd: AsRawFd>(fd: &Fd) -> Result<u64, Error> {
    //file_size_statx(fd)
    file_size_fstat(fd)
}

// TODO how to pass errors back through appropriately?
//impl<W: Write + Seek> Visitor for MyVisitor<W> {
impl Visitor for MyVisitor {
    fn on_file(&mut self, name: &CStr, mut file: File) -> () {
        //let len = file.metadata().unwrap().len();
        let len = file_size(&file).unwrap();

        // self.buf.clear();
        // self.buf.push(ArchiveFormat1Tag::File as u8);
        // self.buf.extend_from_slice(name.to_bytes_with_nul());
        // self.buf.extend_from_slice(&(len as u32).to_le_bytes());
        // self.out.write_all(self.buf.as_slice()).unwrap();

        self.writer.write_all(&[ArchiveFormat1Tag::File as u8]).unwrap();
        self.writer.write_all(name.to_bytes_with_nul()).unwrap();
        self.writer.write_all(&(len as u32).to_le_bytes()).unwrap();
        self.writer.flush().unwrap();

        // TODO io::copy tries a copy_file_range first then falls back to sendfile when the two fds
        // are on different filesystems; this is happening now b/c I'm going from a disk to tmpfs
        // but my initial testing was tmpfs -> tmpfs , inside the vm it will be pmem -> tmpfs so
        // I think we'll want to instead always use sendfile (if we were to go that route, but
        // write seems good enough)
        // docs say it is inadvisable to write through get_mut, but ...
        let outfile = self.writer.get_mut();
        // io::copy(&mut file, outfile).unwrap();
        // TODO maybe configurable whether to use copy_file_range or sendfile
        sendfile_all(&mut file, outfile, len).unwrap();
    }

    fn on_dir(&mut self, name: &CStr) -> () {
        // self.buf.clear();
        // self.buf.push(ArchiveFormat1Tag::Dir as u8);
        // self.buf.extend_from_slice(name.to_bytes_with_nul());
        // self.out.write_all(self.buf.as_slice()).unwrap();

        self.writer.write_all(&[ArchiveFormat1Tag::Dir as u8]).unwrap();
        self.writer.write_all(name.to_bytes_with_nul()).unwrap();
    }

    fn leave_dir(&mut self) -> () {
        //self.out.write_all(&[ArchiveFormat1Tag::Pop as u8]).unwrap();
        self.writer.write_all(&[ArchiveFormat1Tag::Pop as u8]).unwrap();
    }
}

/// args: <input dir> <output file>
fn pack_v1(args: &[String]) {
    let indir = args.get(0).ok_or(Error::NoOutfile).unwrap();
    let outname = args.get(1).ok_or(Error::NoOutfile).unwrap();
    let indirpath = Path::new(indir);
    assert!(indirpath.is_dir(), "{:?} should be a dir", indirpath);
    let fileout = File::create(outname).unwrap();
    let mut visitor = MyVisitor::new(fileout);
    list_dir(indirpath, &mut visitor).unwrap();
    let outfile = visitor.into_file();
    let _len = outfile.metadata().unwrap().len();
    // println!("outfile has total len={len}");
}

// TODO these are semi duplicated with stuff in liblistdir
fn unpack_v1(args: &[String]) {
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

fn copy_file_range_all(filein: &mut File, fileout: &mut File, len: u64) -> Result<(), Error> {
    let fd_in  = filein.as_raw_fd();
    let fd_out = fileout.as_raw_fd();
    let mut len = len;
    while len > 0 {
        let ret = unsafe {
            libc::copy_file_range(fd_in, ptr::null_mut(), fd_out, ptr::null_mut(), len as usize, 0)
        };
        if ret <= 0 { return Err(Error::CopyFileRange); }
        let ret = ret as u64;
        if ret > len { return Err(Error::CopyFileRange); }
        len -= ret;
    }
    Ok(())
}

fn sendfile_all(filein: &mut File, fileout: &mut File, len: u64) -> Result<(), Error> {
    let fd_in  = filein.as_raw_fd();
    let fd_out = fileout.as_raw_fd();
    let mut len = len;
    while len > 0 {
        let ret = unsafe {
            libc::sendfile(fd_out, fd_in, ptr::null_mut(), len as usize)
        };
        if ret <= 0 { return Err(Error::CopyFileRange); }
        let ret = ret as u64;
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
    //println!("use_copy_file={}", use_copy_file);
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
            let size = *size as u64;
            let mut fileout = unsafe {
                let fd = libc::open(filenames_cur.as_ptr() as *const i8, libc::O_CREAT | libc::O_WRONLY, 0o755);
                assert!(fd > 0, "open failed");
                File::from_raw_fd(fd)
            };
            // hmm why didn't i use io::copy here originally?
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
        Some("pack_v0") => { pack_v0(&args[2..]); },
        Some("pack_v1") => { pack_v1(&args[2..]); },
        Some("unpack_v0") => { unpack_v0(&args[2..]); },
        Some("unpack_v1") => { unpack_v1(&args[2..]); },
        Some("unpack_v1_ring") => { unpack_v1_ring(&args[2..]); },
        Some("list_dirs") => { list_dirs(&args[2..]); },
        Some("make_malicious") => { make_malicious_archive(&args[2..]); },
        _ => {
            println!("got args={args:?}");
            println!("pack_v0 <output-file> < <file-list>");
            println!("pack_v1 <input-dir> <output-file>");
            println!("unpack_v0 <input-file> <output-dir> [copy_file_range]");
            println!("unpack_v1 <input-file> <output-dir>");
            println!("unpack_v1_ring <input-file> <output-dir>");
            println!("list_dirs < <file-list>");
        }
    }
}
