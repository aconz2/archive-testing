use std::path::{Path};
use std::ffi::{CStr,CString};
use rustix::fs::{RawDir,FileType};
use std::os::fd::{FromRawFd,AsRawFd,OwnedFd};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

const MAX_DIR_DEPTH: usize = 32;

#[derive(Debug)]
pub enum Error {
    Open,
    //OpenAt,
    Getdents,
    DirTooDeep,
    //NotADir,
    //FdOpenDir,
    Mkdirat,
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

pub fn opendirat<Fd: AsRawFd>(fd: &Fd, name: &CStr) -> Result<OwnedFd, Error> {
    let fd = unsafe {
        let ret = libc::openat(fd.as_raw_fd(), name.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// yeah I know this is all duplicated
pub fn openpathat<Fd: AsRawFd>(fd: &Fd, name: &CStr) -> Result<OwnedFd, Error> {
    let fd = unsafe {
        let ret = libc::openat(fd.as_raw_fd(), name.as_ptr(), libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn mkdirat<Fd: AsRawFd>(fd: &Fd, name: &CStr) -> Result<(), Error> {
    unsafe {
        let ret = libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755);
        if ret < 0 { return Err(Error::Mkdirat); }
        Ok(())
    }
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

pub trait Visitor {
    fn on_file(&mut self, name: &CStr, file: File) -> ();
    fn on_dir(&mut self, name: &CStr) -> ();
    fn leave_dir(&mut self) -> ();
}

fn list_dir2_rec<V: Visitor>(curname: &CStr, curdir: &OwnedFd, v: &mut V, depth: usize) -> Result<(), Error> {
    if depth > MAX_DIR_DEPTH { return Err(Error::DirTooDeep); }

    let mut buf = Vec::with_capacity(4096);
    let mut iter = RawDir::new(&curdir, buf.spare_capacity_mut());

    while let Some(entry) = iter.next() {
        let entry = entry.map_err(|_| Error::Getdents)?;
        // let name = entry.file_name();
        match entry.file_type() {
            FileType::RegularFile => {
                // let name = unsafe { OsStr::from_encoded_bytes_unchecked(entry.file_name().to_bytes()) };
                let name = entry.file_name();
                let _ = v.on_file(name, openat(curdir, name)?);
            },
            FileType::Directory => {
                if entry.file_name() == c"." || entry.file_name() == c".." {
                    continue;
                }
                let newdirfd = opendirat(curdir, entry.file_name())?;
                let curname = entry.file_name();

                v.on_dir(curname);
                list_dir2_rec(curname, &newdirfd, v, depth + 1)?;
                v.leave_dir();
            },
            _ => {}
        }
    }

    Ok(())
}

pub fn list_dir<V: Visitor>(dir: &Path, v: &mut V) -> Result<(), Error> {
    let curname = CString::new(dir.as_os_str().as_bytes()).unwrap();
    let dirfd = opendir(dir)?;
    list_dir2_rec(curname.as_ref(), &dirfd, v, 0)?;
    Ok(())
}
