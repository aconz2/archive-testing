use std::path::Path;
use std::ffi::{CStr};
use rustix::fs::{RawDir,FileType};
use std::os::fd::OwnedFd;
use std::fs::File;

const MAX_DIR_DEPTH: usize = 32;

use crate::common::Error;
use crate::open::{openat,opendirat,opendir};
// #[derive(Debug)]
// pub enum Error {
//     Open,
//     //OpenAt,
//     Getdents,
//     DirTooDeep,
//     //NotADir,
//     //FdOpenDir,
//     Mkdirat,
// }

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

fn list_dir2_rec<V: Visitor>(curdir: &OwnedFd, v: &mut V, depth: usize) -> Result<(), Error> {
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
                list_dir2_rec(&newdirfd, v, depth + 1)?;
                v.leave_dir();
            },
            _ => {}
        }
    }

    Ok(())
}

pub fn list_dir<V: Visitor>(dir: &Path, v: &mut V) -> Result<(), Error> {
    let dirfd = opendir(dir)?;
    list_dir2_rec(&dirfd, v, 0)?;
    Ok(())
}
