extern crate disasm;

use std::env;

fn main() {
    disasm::disasm(env::args_os().nth(1).unwrap()).unwrap();
}
