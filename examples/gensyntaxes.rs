use failure::Error;
use std::path::Path;
use syntect::parsing::SyntaxSetBuilder;
use syntect::dumps;

pub fn main() -> Result<(), Error> {
    let crate_dir = Path::new(file!()).parent().unwrap().parent().unwrap();
    let syntax_dir = crate_dir.join("syntaxes");
    if !syntax_dir.exists() {
        panic!("syntaxes directory not found: {:?}", syntax_dir);
    }
    let mut builder = SyntaxSetBuilder::new();
    builder.add_from_folder(&syntax_dir, false)?;
    let syntaxes = builder.build();
    let output = crate_dir.join("syntaxes.bin");
    dumps::dump_to_file(&syntaxes, &output)?;
    println!("Wrote syntaxes to {:?}", output);
    Ok(())
}
