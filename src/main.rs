use std::process;

use clap::Parser;

use clutch::cli::Args;

fn main() {
    let args = Args::parse();

    match clutch::run(args) {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("clutch: {}", e);
            process::exit(e.exit_code());
        }
    }
}
