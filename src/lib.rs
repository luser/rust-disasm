extern crate addr2line;
extern crate capstone;
extern crate moria;
extern crate object;
extern crate memmap;

#[macro_use] extern crate failure;

use addr2line::Location;
use capstone::{Arch, Capstone, NO_EXTRA_MODE, Mode};
use failure::Error;
use object::{Machine, Object, ObjectSection, SectionKind};
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

fn print_source_line(loc: &SourceLocation, source_lines: &mut HashMap<PathBuf, Option<Vec<String>>>) -> Result<(), Error> {
    if let &mut Some(ref lines) = match source_lines.entry(loc.file.clone()) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            v.insert(read_file_lines(&loc.file).ok())
        }
    } {
        if loc.line > 0 && loc.line <= lines.len() as u64 {
            println!("{:5} {}", loc.line, lines[loc.line as usize - 1]);
        }
    }
    Ok(())
}

fn disasm_sections<'a>(obj: &object::File<'a>, debug_obj: &object::File<'a>) -> Result<(), Error> {
    let (arch, mode) = match obj.machine() {
        Machine::X86 => (Arch::X86, Mode::Mode32),
        Machine::X86_64 => (Arch::X86, Mode::Mode64),
        _ => unimplemented!(),
    };
    let map = addr2line::Context::new(debug_obj).or(Err(DisasmError::Addr2Line))?;
    let mut source_lines = HashMap::new();
    for sect in obj.sections() {
        let name = sect.name().unwrap_or("<unknown>");
        if sect.kind() == SectionKind::Text {
            println!("Disassembly of section {}:", name);
            let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)?;
            let mut last_loc: Option<SourceLocation> = None;
            for i in cs.disasm_all(sect.data(), sect.address())?.iter() {
                let loc = map.find_location(i.address()).or(Err(DisasmError::Addr2Line))?;
                if let Some(Location { file: Some(file), line: Some(line), .. }) = loc {
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
    if obj.has_debug_symbols() {
        disasm_sections(&obj, &obj)
    } else {
        let debug_path = moria::locate_debug_symbols(&obj, path)?;
        let debug_f = File::open(debug_path)?;
        let debug_buf = unsafe { memmap::Mmap::map(&debug_f)? };
        let debug_obj = object::File::parse(&*debug_buf).map_err(|e| DisasmError::Object { reason: e } )?;
        disasm_sections(&obj, &debug_obj)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
