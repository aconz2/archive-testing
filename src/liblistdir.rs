use std::path::{PathBuf,Path};
use std::ffi::{OsStr,OsString,CStr,CString};
use rustix::fs::{RawDir,FileType};
use std::os::fd::{FromRawFd,AsRawFd,OwnedFd};
use std::fs::File;

const MAX_DIR_DEPTH: usize = 32;

#[derive(Debug)]
pub enum Error {
    Open,
    OpenAt,
    Getdents,
    DirTooDeep,
    NotADir,
    FdOpenDir,
}

fn opendir(dir: &Path) -> Result<OwnedFd, Error> {
    let cstr = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe {
        let ret = libc::open(cstr.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn openat<Fd: AsRawFd>(fd: &Fd, name: &CStr) -> Result<File, Error> {
    let fd = unsafe {
        let ret = libc::openat(fd.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn opendirat<Fd: AsRawFd>(fd: &Fd, name: &CStr) -> Result<OwnedFd, Error> {
    let fd = unsafe {
        let ret = libc::openat(fd.as_raw_fd(), name.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// TODO I don't know how to write the lifetime for this to do a non-recursive version
// ----------------
// struct DIR<'a> {
//     file: File,
//     iter: RawDir<'a, &File>,
//     buf: Vec<u8>,
// }
// 
// impl DIR<'_> {
//     fn new(dir: &Path) -> Result<Self, Error> {
//         let file = opendir(dir)?;
//         let mut buf = Vec::with_capacity(8192);
//         let iter = RawDir::new(&file, buf.spare_capacity_mut());
//         Ok(Self { file:file, iter:iter, buf:buf })
//     }
// }
// ----------------


fn list_dir2_rec<F: Fn(&CStr, File) -> (), D: Fn(&CStr) -> ()>(curpath: &mut PathBuf, parentdir: &OwnedFd, iter: &mut RawDir<&OwnedFd>, fcb: &F, dcb: &D, depth: usize) -> Result<(), Error> {
    if depth > MAX_DIR_DEPTH { return Err(Error::DirTooDeep); }
    while let Some(entry) = iter.next() {
        let entry = entry.map_err(|_| Error::Getdents)?;
        match entry.file_type() {
            FileType::RegularFile => {
                // let name = unsafe { OsStr::from_encoded_bytes_unchecked(entry.file_name().to_bytes()) };
                let name = entry.file_name();
                let _ = fcb(name, openat(parentdir, name)?);
                // files.push(curpath.join(name).into());
            },
            FileType::Directory => {
                if entry.file_name() == c"." || entry.file_name() == c".." {
                    continue;
                }
                {
                    let name = unsafe { OsStr::from_encoded_bytes_unchecked(entry.file_name().to_bytes()) };
                    curpath.push(name);
                }
                // dirs.push(curpath.clone().into());
                let _ = dcb(entry.file_name());

                let newdirfd = opendirat(parentdir, entry.file_name())?;
                let mut buf = Vec::with_capacity(4096);
                let mut newiter = RawDir::new(&newdirfd, buf.spare_capacity_mut());

                list_dir2_rec(curpath, &newdirfd, &mut newiter, fcb, dcb, depth + 1)?;
                curpath.pop();
            },
            _ => {}
        }
    }

    Ok(())
}

pub fn list_dir<F: Fn(&CStr, File) -> (), D: Fn(&CStr) -> ()>(dir: &Path, fcb: F, dcb: D) -> Result<(), Error> {
    let mut curpath = PathBuf::new();

    let dirfd = opendir(dir)?;
    let mut buf = Vec::with_capacity(4096);
    let mut iter = RawDir::new(&dirfd, buf.spare_capacity_mut());

    list_dir2_rec(&mut curpath, &dirfd, &mut iter, &fcb, &dcb, 0)?;
    Ok(())
}
