use std::env;
use std::collections::HashSet;
use std::path::Path;
use std::io::stdin;
use std::io::BufRead;
// use std::fs::File;


#[derive(Debug)]
enum Error {
    NoOutfile,
}

/// v0 archive format
/// num_dirs: u32le 
/// num_files: u32le
/// dirnames_size: u32le
/// filenames_size: u32le
/// <dirnames with null bytes>
/// <filenames with null bytes>
/// <num_files x u32le file sizes>
/// <data>

fn create_v0(args: Vec<String>) {
    let outname = args.get(1).ok_or(Error::NoOutfile).unwrap();
    //let outfile = File::create(outname).unwrap();
    let files = {
        let mut acc: Vec<_> = stdin().lock().lines().map(|x| x.unwrap()).collect();
        acc.sort();
        acc
    };
    let mut size = 0;
    let dirs = {
        let mut acc = HashSet::new();
        for file in &files {
            let p = Path::new(&file);
            size += p.metadata().unwrap().len();
            if !p.is_file() { continue; }
            assert!(p.is_file(), "{:?} is not file", p);
            for parent in p.ancestors().skip(1) {
                acc.insert(parent.to_owned());
            }
        }
        let mut acc: Vec<_> = acc.drain().collect();
        acc.sort();
        acc
    };
    //for d in dirs {
    //    println!("{:?}", d);
    //}
    println!("there are {} dirs", dirs.len());
    println!("there are {} files", files.len());
    println!("total bytes of data {}", size);
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
