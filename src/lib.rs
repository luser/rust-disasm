extern crate addr2line;
extern crate capstone;
extern crate gimli;
extern crate moria;
extern crate object;
extern crate memmap;

#[macro_use] extern crate failure;

use addr2line::{Context, Location};
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

#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CpuArch {
    X86,
    X86_64,
}

#[derive(Debug, PartialEq)]
pub struct SourceLocation {
    file: PathBuf,
    line: u64,
}

impl<'a> PartialEq<(&'a Path, u64)> for SourceLocation {
    fn eq(&self, other: &(&'a Path, u64)) -> bool {
        return self.file == other.0 && self.line == other.1;
    }
}

pub trait SourceLookup {
    fn lookup(&mut self, address: u64) -> Option<SourceLocation>;
}

impl<R> SourceLookup for Context<R>
    where
    R: gimli::Reader + Sync,
    R::Offset: Sync,
{
    fn lookup(&mut self, address: u64) -> Option<SourceLocation> {
        self.find_location(address).ok()
            .and_then(|loc| loc)
            .and_then(|Location { file, line, .. }| {
                if let (Some(file), Some(line)) = (file, line) {
                    Some(SourceLocation { file, line })
                } else {
                    None
                }
            })
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

pub fn disasm_bytes(bytes: &[u8],
                    base_address: u64,
                    arch: CpuArch,
                    lookup: &mut SourceLookup) -> Result<(), Error> {
    let (arch, mode) = match arch {
        CpuArch::X86 => (Arch::X86, Mode::Mode32),
        CpuArch::X86_64 => (Arch::X86, Mode::Mode64),
    };
    let mut source_lines = HashMap::new();
    let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)?;
    let mut last_loc: Option<SourceLocation> = None;
    for i in cs.disasm_all(bytes, base_address)?.iter() {
        let loc = lookup.lookup(i.address());
        if let Some(loc) = loc {
            let this_loc = loc;
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
    Ok(())
}

fn disasm_text_sections<'a>(obj: &object::File<'a>,
                            debug_obj: &object::File<'a>) -> Result<(), Error> {
    let mut map = Context::new(debug_obj).or(Err(DisasmError::Addr2Line))?;
    let arch = match obj.machine() {
        Machine::X86 => CpuArch::X86,
        Machine::X86_64 => CpuArch::X86_64,
        a @ _ => return Err(format_err!("Unsupported CPU architecture {:?}", a)),
    };
    for sect in obj.sections() {
        let name = sect.name().unwrap_or("<unknown>");
        if sect.kind() == SectionKind::Text {
            println!("Disassembly of section {}:", name);
            disasm_bytes(sect.data(), sect.address(), arch, &mut map)?;
        }
    }
    Ok(())
}

fn with_file<F>(path: &Path, func: F) -> Result<(), Error>
    where F: Fn(&object::File) -> Result<(), Error>
{
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let obj = object::File::parse(&*buf).map_err(|e| DisasmError::Object { reason: e } )?;
    func(&obj)
}

pub fn disasm_file<P>(path: P) -> Result<(), Error>
    where P: AsRef<Path>,
{
    let path = path.as_ref();
    with_file(path, |obj| {
        if obj.has_debug_symbols() {
            disasm_text_sections(&obj, &obj)
        } else {
            let debug_file = moria::locate_debug_symbols(obj, path)?;
            with_file(&debug_file, |debug_obj| {
                disasm_text_sections(&obj, &debug_obj)
            })
        }
    })
}
