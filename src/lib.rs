use addr2line::{Context, Location};
use atty::Stream;
use capstone::{Arch, Capstone, Insn, Mode, NO_EXTRA_MODE};
use object::{Machine, Object, ObjectSection, SectionKind};
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::StructOpt;
use syntect::util::as_24_bit_terminal_escaped;
use syntect::easy::{HighlightFile, HighlightLines};
use syntect::parsing::{Scope, SyntaxSet};
use syntect::highlighting::{Theme, ThemeSet, Style};
use thiserror::Error;

static THEMES: Lazy<(SyntaxSet, Theme, SyntaxSet)> = Lazy::new(|| {
    let ss = SyntaxSet::load_defaults_newlines();
    let asm_builtins = syntect::dumps::from_binary(include_bytes!("../syntaxes.bin"));
    let ts = ThemeSet::load_defaults();
    let theme = ts.themes.get("base16-ocean.dark").unwrap().clone();
    (ss, theme, asm_builtins)
});

#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("unknown error")]
    Unknown,
    #[error("Bad input filename: {0:?}")]
    BadFilename(PathBuf),
    #[error("addr2line error")]
    Addr2Line,
    #[error("Error parsing object file: {0}")]
    Object(&'static str),
    #[error("{0}")]
    InvalidArgument(String),
    #[error("Unsupported CPU architecture {0:?}")]
    UnsupportedArchitecture(Machine),
    #[error("I/O error: {source:?}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Formatting error: {source:?}")]
    Format {
        #[from]
        source: std::fmt::Error,
    },
    #[error("Disassembly error: {source:?}")]
    Disassembly {
        #[from]
        source: capstone::Error,
    },
    #[error("{0}")]
    Other(Box<dyn std::error::Error>),
}

impl From<failure::Error> for DisasmError {
    fn from(e: failure::Error) -> Self {
        DisasmError::Other(Box::new(e.compat()))
    }
}

pub type Result<T> = std::result::Result<T, DisasmError>;

#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CpuArch {
    X86,
    X86_64,
    ARM64,
}

/// Whether output should be colorized.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Color {
    /// Output colors if stdout is a terminal.
    Auto,
    /// Always output color.
    Yes,
    /// Do not output color.
    No,
}

//TODO: use strum to get a from_str on Color.
impl FromStr for Color {
    type Err = DisasmError;

    fn from_str(s: &str) -> Result<Color> {
        Ok(match s {
            "auto" => Color::Auto,
            "yes" => Color::Yes,
            "no" => Color::No,
            _ => return Err(DisasmError::InvalidArgument(format!("Invalid --color option: {}", s))),
        })
    }
}

/// Information about the source location of an address in a program.
#[derive(Debug, PartialEq)]
pub struct SourceLocation {
    /// The source file.
    pub file: String,
    /// If present, use this for display instead of `file`.
    pub file_display: Option<String>,
    /// The line number within `source_file`.
    pub line: u64,
}

impl SourceLocation {
    pub fn filename(&self) -> Cow<str> {
        self.file_display.as_ref()
            .map(|s| Cow::Borrowed(s.as_str()))
            .unwrap_or_else(|| Cow::Borrowed(&self.file))
    }
}

pub trait SourceLookup {
    fn lookup(&mut self, address: u64) -> Option<SourceLocation>;
}

impl<R> SourceLookup for Context<R>
    where
    R: gimli::Reader,
{
    fn lookup(&mut self, address: u64) -> Option<SourceLocation> {
        self.find_location(address).ok()
            .and_then(|loc| loc)
            .and_then(|Location { file, line, .. }| {
                if let (Some(file), Some(line)) = (file, line) {
                    Some(SourceLocation { file, file_display: None, line })
                } else {
                    None
                }
            })
    }
}

fn read_file_lines<P>(path: P, color: bool) -> io::Result<Vec<String>>
    where P: AsRef<Path>,
{
    let mut lines = vec![];
    if color {
        let (ref ss, ref theme, _) = *THEMES;
        let mut highlighter = HighlightFile::new(path, ss, theme)?;
        let mut line = String::new();
        while highlighter.reader.read_line(&mut line)? > 0 {
            {
                let regions: Vec<(Style, &str)> = highlighter.highlight_lines.highlight(&line, &ss);
                let mut s = as_24_bit_terminal_escaped(&regions[..], false);
                // Clear formatting.
                s.push_str("\x1b[0m");
                lines.push(s);
            }
            line.clear();
        }
    } else {
        let f = File::open(path)?;
        let buf = BufReader::new(f);
        for line in buf.lines() {
            let mut line = line?;
            line.push('\n');
            lines.push(line);
        }
    }
    Ok(lines)
}

fn print_source_line<W: Write>(
    w: &mut W,
    loc: &SourceLocation,
    color: bool,
    source_lines: &mut HashMap<String, Option<Vec<String>>>)
    -> Result<()> {
    if let &mut Some(ref lines) = match source_lines.entry(loc.file.clone()) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            v.insert(read_file_lines(&loc.file, color).ok())
        }
    } {
        if loc.line > 0 && loc.line <= lines.len() as u64 {
            write!(w, "{:5} {}", loc.line, lines[loc.line as usize - 1])?;
        }
    }
    Ok(())
}

fn format_instruction(w: &mut dyn Write, insn: &Insn, colorizer: &mut dyn FnMut(String) -> String) -> Result<()> {
    // This is the number objdump uses.
    const CHUNK_LEN: usize = 7;
    for (i, chunk) in insn.bytes().chunks(CHUNK_LEN).enumerate() {
        write!(w, "   {:08x}:\t", insn.address() + (i*CHUNK_LEN) as u64)?;
        for b in chunk {
            write!(w, "{:02x} ", b)?;
        }
        // Pad out bytes so they're all the same length.
        for _ in 0..(CHUNK_LEN - chunk.len()) {
            write!(w, "   ")?;
        }
        write!(w, "\t")?;
        if i == 0 {
            if let Some(mnemonic) = insn.mnemonic() {
                let mut s = String::new();
                write!(&mut s, "{} ", mnemonic)?;
                if let Some(op_str) = insn.op_str() {
                    write!(&mut s, "{}", op_str)?;
                }
                write!(w, "{}", colorizer(s))?;
            }
        }
        writeln!(w, "")?;
    }
    Ok(())
}

/// Print source-interleaved disassembly for the instructions in `bytes`, treating offsets as
/// relative to `base_address`, with `arch` as the CPU architecture, `lookup` as an object that can
/// provide source information given an address, and optionally highlighting the instruction at
/// `highlight`.
pub fn disasm_bytes(bytes: &[u8],
                    base_address: u64,
                    arch: CpuArch,
                    color: Color,
                    mut highlight: Option<u64>,
                    lookup: &mut dyn SourceLookup) -> Result<()> {
    let (arch, mode, scope) = match arch {
        CpuArch::X86 => (Arch::X86, Mode::Mode32, "source.asm.x86_64"),
        CpuArch::X86_64 => (Arch::X86, Mode::Mode64, "source.asm.x86_64"),
        CpuArch::ARM64 => (Arch::ARM64, Mode::Default, "source.asm.arm"),
    };
    let scope = Scope::new(scope).unwrap();
    let color = match color {
        Color::Auto => atty::is(Stream::Stdout),
        Color::Yes => true,
        Color::No => false,
    };
    let mut asm_colorizer: Box<dyn FnMut(String) -> String> = if color {
        let (_, ref theme, ref asm_ss) = *THEMES;
        let syntax = asm_ss.find_syntax_by_scope(scope).unwrap();
        let mut h = HighlightLines::new(syntax, theme);
        Box::new(move |s: String| {
            let ranges: Vec<(Style, &str)> = h.highlight(&s, asm_ss);
            let mut s = as_24_bit_terminal_escaped(&ranges[..], false);
            s.push_str("\x1b[0m");
            s
        })
    } else {
        Box::new(|s: String| s)
    };
    let mut source_lines = HashMap::new();
    let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)?;
    let mut last_loc: Option<SourceLocation> = None;
    let mut buf = vec![];
    let mut stdout = io::stdout();
    for i in cs.disasm_all(bytes, base_address)?.iter() {
        let loc = lookup.lookup(i.address());
        if let Some(loc) = loc {
            let this_loc = loc;
            match last_loc {
                None => {
                    writeln!(stdout, "{}", this_loc.filename())?;
                    print_source_line(&mut stdout, &this_loc, color, &mut source_lines)?;
                }
                Some(ref last) => {
                    if last.file != this_loc.file {
                        writeln!(stdout, "{}", this_loc.filename())?;
                    }
                    if last.line != this_loc.line {
                        print_source_line(&mut stdout, &this_loc, color, &mut source_lines)?;
                    }

                }
            }
            last_loc = Some(this_loc);
        } else {
            last_loc = None;
        }
        buf.clear();
        if let Ok(_) = format_instruction(&mut buf, &i, &mut asm_colorizer) {
            stdout.write_all(&buf)?;
            match highlight {
                Some(v) if v <= i.address() => {
                    highlight = None;
                    for b in buf.iter() {
                        if *b == b'\t' {
                            write!(stdout, "\t")?;
                        } else if *b != b'\n' {
                            write!(stdout, "^")?;
                        }
                    }
                    writeln!(stdout, "")?;
                }
                _ => {}
            }
        }
    }
    writeln!(stdout, "")?;
    Ok(())
}

fn disasm_text_sections<'a>(obj: &object::File<'a>,
                            debug_obj: &object::File<'a>,
                            color: Color) -> Result<()> {
    let mut map = Context::new(debug_obj).or(Err(DisasmError::Addr2Line))?;
    let arch = match obj.machine() {
        Machine::X86 => CpuArch::X86,
        Machine::X86_64 => CpuArch::X86_64,
        a @ _ => return Err(DisasmError::UnsupportedArchitecture(a)),
    };
    for sect in obj.sections() {
        let name = sect.name().unwrap_or("<unknown>");
        if sect.kind() == SectionKind::Text {
            writeln!(io::stdout(), "Disassembly of section {}:", name)?;
            disasm_bytes(sect.data().as_ref(), sect.address(), arch, color, None, &mut map)?;
        }
    }
    Ok(())
}

fn with_file<F>(path: &Path, func: F) -> Result<()>
    where F: Fn(&object::File) -> Result<()>
{
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let obj = object::File::parse(&*buf).map_err(DisasmError::Object)?;
    func(&obj)
}

/// Print source-interleaved disassembly for the instructions in any text sections in the
/// binary file at `path`.
pub fn disasm_file<P>(path: P, color: Color) -> Result<()>
    where P: AsRef<Path>,
{
    let path = path.as_ref();
    with_file(path, |obj| {
        if obj.has_debug_symbols() {
            disasm_text_sections(&obj, &obj, color)
        } else {
            let debug_file = moria::locate_debug_symbols(obj, path)?;
            with_file(&debug_file, |debug_obj| {
                disasm_text_sections(&obj, &debug_obj, color)
            })
        }
    })
}

#[derive(StructOpt)]
#[structopt(name = "disasm", about = "Print source-interleaved disassembly for a binary")]
struct Opt {
    #[structopt(long = "color", help = "Enable colored output")]
    color: Option<Color>,
    #[structopt(help = "Binary to disassemble", parse(from_os_str))]
    binary: PathBuf,
}

pub fn main() -> Result<()> {
    let opt = Opt::from_args();
    match disasm_file(&opt.binary, opt.color.unwrap_or(Color::Auto)) {
        Err(DisasmError::Io { source }) if source.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        o @ _  => o,
    }
}
