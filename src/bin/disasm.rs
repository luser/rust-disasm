extern crate disasm;

fn main() {
    match disasm::main() {
        Ok(_) => {},
        Err(e) => eprintln!("{}", e),
    }
}
