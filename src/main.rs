use std::env;
use std::collections::HashSet;
use std::path::Path;
use std::io;
use std::io::{stdin,BufRead,Write};
use std::ffi::OsString;
use std::os::unix::prelude::OsStrExt;
use std::fs::File;


#[derive(Debug)]
enum Error {
    NoOutfile,
}

fn join_bytes<'a, I: Iterator<Item = &'a [u8]>>(xs: I) -> Vec<u8> {
    let mut acc: Vec<u8> = vec![];
    for x in xs {
        acc.extend_from_slice(x);
        acc.push(0)
    }
    acc
}

/// v0 archive format
/// num_dirs: u32le 
/// num_files: u32le
/// dirnames_size: u32le
/// filenames_size: u32le
/// <dirnames with null bytes> of length dirnames_size bytes
/// <filenames with null bytes> of length filenames_size bytes
/// <num_files x u32le file sizes> of length num_files * 4 bytes
/// <data>
/// ---
/// input is line separated pathnames relative to cwd
/// ---
/// args <output file>
fn create_v0(args: Vec<String>) {
    let outname = args.get(2).ok_or(Error::NoOutfile).unwrap();
    let mut outfile = File::create(outname).unwrap();
    let files = {
        let mut acc: Vec<_> = stdin().lock().lines().map(|x| x.unwrap()).collect();
        acc.sort();
        acc
    };
    let mut size = 0;
    let dirs = {
        let mut acc = HashSet::new();
        let empty = OsString::new();
        for file in &files {
            let p = Path::new(&file);
            if !p.is_file() { continue; }
            size += p.metadata().unwrap().len();
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
    dbg!(&dirs);
    println!("there are {} dirs", dirs.len());
    println!("there are {} files", files.len());
    println!("total bytes of data {}", size);
    println!("filenames len {}", filesb.len());
    println!("dirsb len {}", dirsb.len());
    println!("writing to {}", outname);
    for i in vec![dirs.len(), files.len(), dirsb.len(), filesb.len()] {
        outfile.write(&(i as u32).to_le_bytes()).unwrap();
    }
    outfile.write(&dirsb).unwrap();
    outfile.write(&filesb).unwrap();
    for file in &files {
        let mut f = File::open(file).unwrap();
        io::copy(&mut f, &mut outfile).unwrap();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("create_v0") => { create_v0(args); },
        _ => {
            println!("create_v0 <>");
        }
    }
}
