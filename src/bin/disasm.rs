extern crate disasm;

use std::env;

fn main() {
    match disasm::disasm_file(env::args_os().nth(1).unwrap()) {
        Ok(_) => {},
        Err(e) => eprintln!("{}", e),
    }
}
