extern crate addr2line;
extern crate capstone;
extern crate goblin;
extern crate moria;
extern crate object;
extern crate memmap;

#[macro_use] extern crate failure;

use addr2line::Mapping;
use capstone::{Arch, Capstone, NO_EXTRA_MODE, Mode};
use failure::Error;
use goblin::mach::constants::SECT_TEXT;
use object::{Machine, Object, ObjectSection};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Fail)]
pub enum DisasmError {
    #[fail(display = "unknown error")]
    Unknown,
    #[fail(display = "Bad input filename: {:?}", filename)]
    BadFilename { filename: PathBuf },
    #[fail(display = "addr2line error")]
    Addr2Line,
    #[fail(display = "Error parsing object file: {}", reason)]
    Object { reason: &'static str },
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

fn disasm_sections<'a>(obj: &object::File<'a>, path: &Path) -> Result<(), Error> {
    let (arch, mode) = match obj.machine() {
        Machine::X86 => (Arch::X86, Mode::Mode32),
        Machine::X86_64 => (Arch::X86, Mode::Mode64),
        _ => unimplemented!(),
    };
    let mut map = if obj.has_debug_symbols() {
        Mapping::new(path).or(Err(DisasmError::Addr2Line))?
    } else {
        let debug_file = moria::locate_debug_symbols(obj, path)?;
        Mapping::new(debug_file).or(Err(DisasmError::Addr2Line))?
    };
    let mut source_lines = HashMap::new();
    for sect in obj.sections() {
        let name = sect.name().unwrap_or("<unknown>");
        if name == SECT_TEXT {
            println!("Disassembly of section {}:", name);
            let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)?;
            let mut last_loc: Option<SourceLocation> = None;
            for i in cs.disasm_all(sect.data(), sect.address())?.iter() {
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
    Ok(())
}

pub fn disasm<P>(path: P) -> Result<(), Error>
    where P: AsRef<Path>,
{
    let path = path.as_ref();
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };

    let obj = object::File::parse(&*buf).map_err(|e| DisasmError::Object { reason: e } )?;
    disasm_sections(&obj, path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
