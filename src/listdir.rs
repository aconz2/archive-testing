use std::path::Path;
use std::ffi::OsString;
use std::os::fd::{RawFd,FromRawFd,AsRawFd,OwnedFd};
use std::fs::{ReadDir};
use std::path::PathBuf;
use std::ffi::{CStr,OsStr,CString};
use rustix::fs::{RawDir,FileType};
use rustix::fd::IntoRawFd;
use std::env;

const MAX_DIR_DEPTH: usize = 32;

#[derive(Debug)]
enum Error {
    Entry,
    ReadDir,
    FileType,
    Open,
    OpenAt,
    Getdents,
    DirTooDeep,
    NotADir,
    FdOpenDir,
}

// -- begin section of reimplementing an opendirat
fn dirent_name_ptr(dirent: &*const libc::dirent) -> *const i8 {
    use std::mem;
    const OFFSET: isize = mem::offset_of!(libc::dirent, d_name) as isize;
    unsafe { dirent.byte_offset(OFFSET) as *const i8 }
}

fn dirent_name_osstr(dirent: &*const libc::dirent) -> &OsStr {
    let cname = unsafe { CStr::from_ptr(dirent_name_ptr(dirent)) };
    unsafe { OsStr::from_encoded_bytes_unchecked(cname.to_bytes()) }
}

fn dirent_name_cstr(dirent: &*const libc::dirent) -> &CStr {
    unsafe { CStr::from_ptr(dirent_name_ptr(dirent)) }
}

struct DIR {
    dirp: *mut libc::DIR,
    fd: RawFd, // we have to keep this around so we can do openat
}

impl Drop for DIR {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::closedir(self.dirp);  // this closes the fd
        }
    }
}

fn fdopendir(fd: OwnedFd) -> Result<*mut libc::DIR, Error> {
    let p = unsafe {
        libc::fdopendir(fd.into_raw_fd())  // transfers ownership
    };
    if p.is_null() { return Err(Error::FdOpenDir); }
    Ok(p)
}

impl DIR {
    fn open(path: &Path) -> Result<Self, Error> {
        let fd = opendir(path)?;
        // this calls fcntl F_GETFD to make sure the fd isn't opened with O_PATH
        // then it unconditionally calls fcntl F_SETFD O_CLOEXEC
        // and it calls stat, so 3 syscalls :(
        let rfd = fd.as_raw_fd();  // smuggle a copy
        let dirp = fdopendir(fd)?;
        Ok(Self { dirp: dirp, fd: rfd })
    }

    fn readdir(&mut self) -> Option<*const libc::dirent> {
        let ret = unsafe { libc::readdir(self.dirp) };
        if ret.is_null() { return None; }
        Some(ret)
    }

    fn openat(&self, dirent: *const libc::dirent) -> Result<Self, Error> {
        let fd = unsafe {
            let ret = libc::openat(self.fd, dirent_name_ptr(&dirent), libc::O_RDONLY | libc::O_CLOEXEC);
            if ret < 0 { return Err(Error::OpenAt) }
            OwnedFd::from_raw_fd(ret)
        };
        let rfd = fd.as_raw_fd(); // smuggle a copy
        let dirp = fdopendir(fd)?;
        Ok(Self { dirp: dirp, fd: rfd })
    }
}

fn list_dir_c_rec(curpath: &mut PathBuf, dirp: &mut DIR, dirs: &mut Vec::<OsString>, files: &mut Vec::<OsString>, depth: usize) -> Result<(), Error> {
    if depth > MAX_DIR_DEPTH { return Err(Error::DirTooDeep); }

    while let Some(dirent) = dirp.readdir() {
        let d_type = unsafe { (*dirent).d_type };
        match d_type {
            libc::DT_REG => {
                files.push(curpath.join(dirent_name_osstr(&dirent)).into());
            },
            libc::DT_DIR => {
                let cstr = dirent_name_cstr(&dirent).to_bytes();
                if cstr == b"." || cstr == b".." {
                    continue;
                }
                dirs.push(curpath.join(dirent_name_osstr(&dirent)).into());
                curpath.push(dirent_name_osstr(&dirent));
                let mut newdir = dirp.openat(dirent)?;
                list_dir_c_rec(curpath, &mut newdir, dirs, files, depth + 1)?;
                curpath.pop();
            }
            // TODO apparently DT_UNKNOWN is possible on some fs's like xfs and you have to do a
            // stat call
            _ => {}
        }
    }
    Ok(())
}

fn list_dir_c(dir: &Path) -> Result<(Vec<OsString>, Vec<OsString>), Error> {
    let mut dirp = DIR::open(dir)?;
    let mut dirs: Vec::<OsString> = vec![];
    let mut files: Vec::<OsString> = vec![];
    let mut curpath = PathBuf::new();
    list_dir_c_rec(&mut curpath, &mut dirp, &mut dirs, &mut files, 0)?;
    Ok((dirs, files))
}

// -- end section of opendirat


fn opendir(dir: &Path) -> Result<OwnedFd, Error> {
    let cstr = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe {
        let ret = libc::open(cstr.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC);
        if ret < 0 { return Err(Error::Open); }
        ret
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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

fn list_dir2_rec(curpath: &mut PathBuf, parentdir: &OwnedFd, iter: &mut RawDir<&OwnedFd>, dirs: &mut Vec::<OsString>, files: &mut Vec::<OsString>, depth: usize) -> Result<(), Error> {
    if depth > MAX_DIR_DEPTH { return Err(Error::DirTooDeep); }
    while let Some(entry) = iter.next() {
        let entry = entry.map_err(|_| Error::Getdents)?;
        match entry.file_type() {
            FileType::RegularFile => {
                let name = unsafe { OsStr::from_encoded_bytes_unchecked(entry.file_name().to_bytes()) };
                files.push(curpath.join(name).into());
            },
            FileType::Directory => {
                if entry.file_name() == c"." || entry.file_name() == c".." {
                    continue;
                }
                let name = unsafe { OsStr::from_encoded_bytes_unchecked(entry.file_name().to_bytes()) };
                curpath.push(name);
                dirs.push(curpath.clone().into());

                let newdirfd = opendirat(parentdir, entry.file_name())?;
                let mut buf = Vec::with_capacity(4096);
                let mut newiter = RawDir::new(&newdirfd, buf.spare_capacity_mut());

                list_dir2_rec(curpath, &newdirfd, &mut newiter, dirs, files, depth + 1)?;
                curpath.pop();
            },
            _ => {}
        }
    }

    Ok(())
}

fn list_dir2(dir: &Path) -> Result<(Vec<OsString>, Vec<OsString>), Error> {
    let mut curpath = PathBuf::new();
    let mut dirs: Vec::<OsString> = vec![];
    let mut files: Vec::<OsString> = vec![];

    let dirfd = opendir(dir)?;
    let mut buf = Vec::with_capacity(4096);
    let mut iter = RawDir::new(&dirfd, buf.spare_capacity_mut());

    list_dir2_rec(&mut curpath, &dirfd, &mut iter, &mut dirs, &mut files, 0)?;
    files.sort();
    dirs.sort();
    Ok((dirs, files))
}

fn list_dir_rec(curpath: &mut PathBuf, dir: &Path, dirs: &mut Vec::<OsString>, files: &mut Vec::<OsString>, depth: usize) -> Result<(), Error> {
    if depth > MAX_DIR_DEPTH { return Err(Error::DirTooDeep); }
    // TODO it would be great to have a read_dir for a direntry so it could use openat
    for entry in dir.read_dir().map_err(|_| Error::ReadDir)? {
        let entry = entry.map_err(|_| Error::Entry)?;
        let ftype = entry.file_type().map_err(|_| Error::FileType)?;
        if ftype.is_file() {
            files.push(curpath.join(entry.file_name()).into());
        } else if ftype.is_dir() {
            curpath.push(entry.file_name());
            dirs.push(curpath.clone().into());
            list_dir_rec(curpath, entry.path().as_ref(), dirs, files, depth + 1)?;
        }
    }
    curpath.pop();
    Ok(())
}

fn list_dir(dir: &Path) -> Result<(Vec<OsString>, Vec<OsString>), Error> {
    if !dir.is_dir() { return Err(Error::NotADir); }
    let mut dirs: Vec::<OsString> = vec![];
    let mut files: Vec::<OsString> = vec![];
    let mut curpath = PathBuf::new();
    list_dir_rec(&mut curpath, dir, &mut dirs, &mut files, 0)?;
    files.sort();
    dirs.sort();
    Ok((dirs, files))
}

fn list_dir_nr(dir: &Path) -> Result<(Vec<OsString>, Vec<OsString>), Error> {
    if !dir.is_dir() { return Err(Error::NotADir); }
    let mut dirs: Vec::<OsString> = vec![];
    let mut files: Vec::<OsString> = vec![];
    let mut curpath = PathBuf::new();
    let mut stack: Vec::<ReadDir> = Vec::with_capacity(32);
    stack.push(dir.read_dir().map_err(|_| Error::ReadDir)?);
    while let Some(ref mut reader) = stack.last_mut() {
        match reader.next() {
            None => {
                curpath.pop();
                stack.pop();
            },
            Some(Ok(entry)) => {
                let ftype = entry.file_type().map_err(|_| Error::FileType)?;
                if ftype.is_file() {
                    files.push(curpath.join(entry.file_name()).into());
                } else if ftype.is_dir() {
                    curpath.push(entry.file_name());
                    stack.push(entry.path().read_dir().map_err(|_| Error::ReadDir)?);
                    dirs.push(curpath.clone().into());
                }
            },
            Some(Err(_)) => { return Err(Error::ReadDir); }
        }
    }
    files.sort();
    dirs.sort();
    Ok((dirs, files))
}

fn list_dir_wd(dir: &Path) -> Result<(Vec<OsString>, Vec<OsString>), Error> {
    use walkdir::WalkDir;
    if !dir.is_dir() { return Err(Error::NotADir); }
    let mut dirs: Vec::<OsString> = vec![];
    let mut files: Vec::<OsString> = vec![];
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_dir() {
            dirs.push(entry.path().into());
        } else if entry.file_type().is_file() {
            files.push(entry.path().into());
        }
    }
    files.sort();
    dirs.sort();
    Ok((dirs, files))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (mut files, mut dirs) = match (args.get(1).map(|s| s.as_str()), args.get(2).map(|s| s.as_str())) {
        (Some("list_dir"), Some(d)) => { list_dir(Path::new(d)) },
        (Some("list_dir2"), Some(d)) => { list_dir2(Path::new(d)) },
        (Some("list_dir_c"), Some(d)) => { list_dir_c(Path::new(d)) },
        (Some("list_dir_nr"), Some(d)) => { list_dir_nr(Path::new(d)) },
        (Some("list_dir_wd"), Some(d)) => { list_dir_wd(Path::new(d)) },
        (Some(_), None) |
        _ => {
            println!("listdir <list_dir|list_dir2|list_dir_c|list_dir_nr|list_dir_wd> <DIR>");
            return;
        }
    }.unwrap();
    files.sort();
    dirs.sort();
    for dir in dirs {
        println!("dir {dir:?}");
    }
    for file in files {
        println!("file {file:?}");
    }
}
