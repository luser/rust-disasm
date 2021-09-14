use addr2line::{Context, Location};
use atty::Stream;
use fallible_iterator::FallibleIterator;
use object::{self, Architecture, Object, ObjectSection, SectionKind};
use once_cell::sync::Lazy;
#[cfg(unix)]
use pager::Pager;
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::StructOpt;
use syntect::easy::{HighlightFile, HighlightLines};
use syntect::highlighting::{Style, Theme, ThemeSet};
use syntect::parsing::{Scope, SyntaxSet};
use syntect::util::as_24_bit_terminal_escaped;
use thiserror::Error;
use yaxpeax_arch::{AddressBase, Arch, DecodeError, Decoder, LengthedInstruction, Reader, U8Reader};
use num_traits::identities::Zero;

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
    #[error("Couldn't locate debug symbols for {0:?}")]
    NoDebugSymbols(PathBuf),
    #[error("addr2line error")]
    Addr2Line,
    #[error("Error parsing object file: {source}")]
    Object {
        #[from]
        source: object::Error,
    },
    #[error("{0}")]
    InvalidArgument(String),
    #[error("Unsupported CPU architecture {0:?}")]
    UnsupportedArchitecture(Architecture),
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
    #[error("Disassembly error: {0}")]
    Disassembly(&'static str),
    #[error("{0}")]
    Other(Box<dyn std::error::Error>),
}

impl From<failure::Error> for DisasmError {
    fn from(e: failure::Error) -> Self {
        DisasmError::Other(Box::new(e.compat()))
    }
}

impl From<yaxpeax_arm::armv8::a64::DecodeError> for DisasmError {
    fn from(e: yaxpeax_arm::armv8::a64::DecodeError) -> Self {
        DisasmError::Disassembly(e.description())
    }
}

impl From<yaxpeax_x86::amd64::DecodeError> for DisasmError {
    fn from(e: yaxpeax_x86::amd64::DecodeError) -> Self {
        DisasmError::Disassembly(e.description())
    }
}

impl From<yaxpeax_x86::protected_mode::DecodeError> for DisasmError {
    fn from(e: yaxpeax_x86::protected_mode::DecodeError) -> Self {
        DisasmError::Disassembly(e.description())
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
            _ => {
                return Err(DisasmError::InvalidArgument(format!(
                    "Invalid --color option: {}",
                    s
                )))
            }
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
    pub line: u32,
}

impl SourceLocation {
    pub fn filename(&self) -> Cow<str> {
        self.file_display
            .as_ref()
            .map(|s| Cow::Borrowed(s.as_str()))
            .unwrap_or_else(|| Cow::Borrowed(&self.file))
    }
}

pub trait SourceLookup {
    fn lookup<'a>(&'a mut self, address: u64) -> Box<dyn Iterator<Item = SourceLocation> + 'a>;
}

impl<R> SourceLookup for Context<R>
where
    R: gimli::Reader,
{
    fn lookup<'a>(&'a mut self, address: u64) -> Box<dyn Iterator<Item = SourceLocation> + 'a> {
        match self.find_frames(address) {
            Err(_) => Box::new(std::iter::empty()),
            Ok(it) => {
                let mut frames: Vec<SourceLocation> = it
                    .iterator()
                    // This is an iterator whose items are Result<Option<Frame>>
                    // Frame has a location that's an Option<Location>.
                    .filter_map(|f| f.ok().and_then(|inner| inner.location))
                    .filter_map(|Location { file, line, .. }| {
                        if let (Some(file), Some(line)) = (file, line) {
                            Some(SourceLocation {
                                file: file.to_owned(),
                                file_display: None,
                                line,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                frames.reverse();
                Box::new(frames.into_iter())
            }
        }
    }
}

fn read_file_lines<P>(path: P, color: bool) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
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

struct SourceLinePrinter {
    source_lines: HashMap<OsString, Option<Vec<String>>>,
}

impl SourceLinePrinter {
    pub fn new() -> Self {
        SourceLinePrinter {
            source_lines: HashMap::new(),
        }
    }

    pub fn print_source_line<W: Write>(
        &mut self,
        w: &mut W,
        loc: &SourceLocation,
        color: bool,
    ) -> Result<()> {
        let f = OsStr::new(&loc.file);
        if let &mut Some(ref lines) = match self.source_lines.entry(f.to_os_string()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(read_file_lines(&f, color).ok()),
        } {
            if loc.line > 0 && loc.line <= lines.len() as u32 {
                write!(w, "{:5} {}", loc.line, lines[loc.line as usize - 1])?;
            }
        }
        Ok(())
    }
}

fn format_instruction(
    w: &mut dyn Write,
    insn: String,
    address: u64,
    bytes: &[u8],
    colorizer: &mut dyn FnMut(String) -> String,
) -> Result<()> {
    // This is the number objdump uses.
    const CHUNK_LEN: usize = 7;
    for (i, chunk) in bytes.chunks(CHUNK_LEN).enumerate() {
        let current = address + (i * CHUNK_LEN) as u64;
        write!(w, "   {:08x}:\t", current)?;
        for b in chunk {
            write!(w, "{:02x} ", b)?;
        }
        // Pad out bytes so they're all the same length.
        for _ in 0..(CHUNK_LEN - chunk.len()) {
            write!(w, "   ")?;
        }
        write!(w, "\t")?;
        if i == 0 {
            write!(w, "{}", colorizer(insn.clone()))?;
        }
        writeln!(w, "")?;
    }
    Ok(())
}

/// Print source-interleaved disassembly for the instructions in `bytes`, treating offsets as
/// relative to `base_address`, with `arch` as the CPU architecture, `lookup` as an object that can
/// provide source information given an address, and optionally highlighting the instruction at
/// `highlight`.
pub fn disasm_bytes(
    bytes: &[u8],
    base_address: u64,
    arch: CpuArch,
    color: Color,
    highlight: Option<u64>,
    lookup: &mut dyn SourceLookup,
) -> Result<()> {
    match arch {
        CpuArch::X86 => disasm_bytes_arch::<yaxpeax_x86::protected_mode::Arch>(
            bytes,
            base_address as u32,
            color,
            highlight,
            lookup,
            "source.asm.x86_64",
        ),
        CpuArch::X86_64 => disasm_bytes_arch::<yaxpeax_x86::amd64::Arch>(
            bytes,
            base_address,
            color,
            highlight,
            lookup,
            "source.asm.x86_64",
        ),
        CpuArch::ARM64 => disasm_bytes_arch::<yaxpeax_arm::armv8::a64::ARMv8>(
            bytes,
            base_address,
            color,
            highlight,
            lookup,
            "source.asm.arm",
        ),
    }
}

fn disasm_bytes_arch<A>(
    bytes: &[u8],
    base_address: A::Address,
    color: Color,
    mut highlight: Option<u64>,
    lookup: &mut dyn SourceLookup,
    asm_scope: &'static str,
) -> Result<()>
where
    A: Arch,
    A::Instruction: std::fmt::Display,
    A::Address: Into<u64>,
    DisasmError: From<A::DecodeError>,
    for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
{
    let scope = Scope::new(asm_scope).unwrap();
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
    let mut source_printer = SourceLinePrinter::new();
    let mut reader = U8Reader::new(bytes);
    let mut inst_offset = reader.total_offset();
    let decoder = A::Decoder::default();
    let mut decode_res = decoder.decode(&mut reader);
    let mut address = A::Address::zero();
    let mut last_loc: Option<SourceLocation> = None;
    let mut buf = vec![];
    let mut stdout = io::stdout();
    loop {
        let inst = decode_res?;
        let abs_address = address + base_address;
        let locs = lookup.lookup(abs_address.into());
        for loc in locs {
            let this_loc = loc;
            match last_loc {
                None => {
                    writeln!(stdout, "{}", this_loc.filename())?;
                    source_printer.print_source_line(&mut stdout, &this_loc, color)?;
                }
                Some(ref last) => {
                    if last.file != this_loc.file {
                        writeln!(stdout, "{}", this_loc.filename())?;
                    }
                    if last.line != this_loc.line {
                        source_printer.print_source_line(&mut stdout, &this_loc, color)?;
                    }
                }
            }
            last_loc = Some(this_loc);
        }
        buf.clear();
        let inst_bytes = &bytes[inst_offset.to_linear()..(inst_offset + inst.len()).to_linear()];
        if let Ok(_) = format_instruction(
            &mut buf,
            inst.to_string(),
            abs_address.into(),
            inst_bytes,
            &mut asm_colorizer,
        ) {
            stdout.write_all(&buf)?;
            match highlight {
                Some(v) if v <= address.to_linear() as u64 => {
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
        address += inst.len();
        if address.to_linear() >= bytes.len() {
            break;
        }
        decode_res = decoder.decode(&mut reader);
        inst_offset = reader.total_offset();
    }
    writeln!(stdout, "")?;
    Ok(())
}

fn disasm_text_sections<'a>(
    obj: &object::File<'a>,
    debug_obj: &object::File<'a>,
    color: Color,
) -> Result<()> {
    let mut map = Context::new(debug_obj).or(Err(DisasmError::Addr2Line))?;
    let arch = match obj.architecture() {
        Architecture::I386 => CpuArch::X86,
        Architecture::X86_64 => CpuArch::X86_64,
        Architecture::Aarch64 => CpuArch::ARM64,
        a @ _ => return Err(DisasmError::UnsupportedArchitecture(a)),
    };
    for sect in obj.sections() {
        let name = sect.name().unwrap_or("<unknown>");
        if sect.kind() == SectionKind::Text {
            writeln!(io::stdout(), "Disassembly of section {}:", name)?;
            disasm_bytes(
                sect.data()?.as_ref(),
                sect.address(),
                arch,
                color,
                None,
                &mut map,
            )?;
        }
    }
    Ok(())
}

fn with_file<F>(path: &Path, func: F) -> Result<()>
where
    F: Fn(&object::File) -> Result<()>,
{
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let obj = object::File::parse(&*buf)?;
    func(&obj)
}

/// Print source-interleaved disassembly for the instructions in any text sections in the
/// binary file at `path`.
pub fn disasm_file<P>(path: P, color: Color) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    with_file(path, |obj| {
        let debug_file_res = locate_dwarf::locate_debug_symbols(obj, path);
        if obj.has_debug_symbols() || match debug_file_res { Err(_) | Ok(None) => true, _ => false } {
            disasm_text_sections(&obj, &obj, color)
        } else {
            let debug_file: PathBuf = debug_file_res.ok().flatten().ok_or_else(|| DisasmError::NoDebugSymbols(path.to_owned()))?;
            with_file(&debug_file, |debug_obj| {
                disasm_text_sections(&obj, &debug_obj, color)
            })
        }
    })
}

#[derive(StructOpt)]
#[structopt(
    name = "disasm",
    about = "Print source-interleaved disassembly for a binary"
)]
struct Opt {
    #[structopt(long = "color", help = "Enable colored output")]
    color: Option<Color>,
    #[structopt(help = "Binary to disassemble", parse(from_os_str))]
    binary: PathBuf,
}

pub fn main() -> Result<()> {
    let opt = Opt::from_args();
    // Check for a tty before swapping it out for a pager.
    let color = opt.color.unwrap_or_else(|| {
        if atty::is(Stream::Stdout) {
            Color::Yes
        } else {
            Color::No
        }
    });
    #[cfg(unix)]
    Pager::with_pager("less -FRSX").setup();

    match disasm_file(&opt.binary, color) {
        Err(DisasmError::Io { source }) if source.kind() == std::io::ErrorKind::BrokenPipe => {
            Ok(())
        }
        o @ _ => o,
    }
}
