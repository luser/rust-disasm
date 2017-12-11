extern crate addr2line;
extern crate capstone;
extern crate goblin;

#[macro_use] extern crate failure;

use addr2line::Mapping;
use capstone::{Arch, Capstone, NO_EXTRA_MODE, Mode};
use failure::Error;
use goblin::Object;
use goblin::mach::{Mach, MachO};
use goblin::mach::constants::SECT_TEXT;
use goblin::mach::constants::cputype;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Fail)]
pub enum DisasmError {
    #[fail(display = "unknown error")]
    Unknown,
    #[fail(display = "Bad input filename: {:?}", filename)]
    BadFilename { filename: PathBuf },
    #[fail(display = "addr2line error")]
    Addr2Line,
}

#[derive(Debug, PartialEq)]
struct SourceLocation {
    file: PathBuf,
    line: u64,
}

impl<'a> PartialEq<(&'a Path, u64)> for SourceLocation {
    fn eq(&self, other: &(&'a Path, u64)) -> bool {
        return self.file == other.0 && self.line == other.1;
    }
}

fn read_file<P>(path: P) -> io::Result<Vec<u8>>
    where P: AsRef<Path>,
{
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn read_file_lines<P>(path: P) -> io::Result<Vec<String>>
    where P: AsRef<Path>,
{
    let f = File::open(path)?;
    let buf = BufReader::new(f);
    let mut lines = vec![];
    for line in buf.lines() {
        lines.push(line?);
    }
    Ok(lines)
}

fn print_source_line(loc: &SourceLocation, source_lines: &mut HashMap<PathBuf, Vec<String>>) -> Result<(), Error> {
    let lines = match source_lines.entry(loc.file.clone()) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            v.insert(read_file_lines(&loc.file)?)
        }
    };
    if loc.line < lines.len() as u64 {
        println!("{:5} {}", loc.line, lines[loc.line as usize]);
    }
    Ok(())
}


fn locate_dsym(path: &Path) -> Result<Option<PathBuf>, Error> {
    let filename = path.file_name().ok_or(DisasmError::BadFilename { filename: path.to_owned() })?;
    let mut dsym = filename.to_owned();
    dsym.push(".dSYM");
    let f = path.with_file_name(&dsym).join("Contents/Resources/DWARF").join(filename);
    if f.exists() {
        Ok(Some(f))
    } else {
        Ok(None)
    }
}

fn parse_mach<'a>(mach: &MachO<'a>, path: &Path) -> Result<(), Error> {
    let dsym = locate_dsym(path)?;
    let debug_file = dsym.as_ref().map(|d| d.as_ref()).unwrap_or(path);
    let (arch, mode) = match mach.header.cputype {
        cputype::CPU_TYPE_X86 => (Arch::X86, Mode::Mode32),
        cputype::CPU_TYPE_X86_64 => (Arch::X86, Mode::Mode64),
        _ => unimplemented!(),
    };
    let mut map = Mapping::new(debug_file).or(Err(DisasmError::Addr2Line))?;
    let mut source_lines = HashMap::new();
    for seg in mach.segments.iter() {
        for (sect, data) in seg.sections()? {
            let name = sect.name()?;
            if name == SECT_TEXT {
                println!("Disassembly of section {}:", name);
                let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)?;
                let mut last_loc: Option<SourceLocation> = None;
                for i in cs.disasm_all(data, sect.addr)?.iter() {
                    let loc = map.locate(i.address()).or(Err(DisasmError::Addr2Line))?;
                    if let Some((file, Some(line), _)) = loc {
                        let this_loc = SourceLocation { file, line };
                        match last_loc {
                            None => {
                                println!("{}", this_loc.file.to_string_lossy());
                                print_source_line(&this_loc, &mut source_lines)?;
                            }
                            Some(ref last) => {
                                if last.file != this_loc.file {
                                    println!("{}", this_loc.file.to_string_lossy());
                                }
                                if last.line != this_loc.line {
                                    print_source_line(&this_loc, &mut source_lines)?;
                                }

                            }
                        }
                        last_loc = Some(this_loc);
                    } else {
                        last_loc = None;
                    }
                    println!("{}", i);
                }
                println!("");
            }
        }
    }
    Ok(())
}

pub fn disasm<P>(path: P) -> Result<(), Error>
    where P: AsRef<Path>,
{
    let buf = read_file(path.as_ref())?;
    match Object::parse(&buf)? {
        Object::Elf(_elf) => {
            unimplemented!()
        },
        Object::PE(_pe) => {
            unimplemented!()
        },
        Object::Mach(mach) => {
            match mach {
                Mach::Fat(_fat) => unimplemented!(),
                Mach::Binary(mach) => parse_mach(&mach, path.as_ref())?,
            }
        },
        Object::Archive(_archive) => {
            unimplemented!()
        },
        Object::Unknown(_magic) => {
            unimplemented!()
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
