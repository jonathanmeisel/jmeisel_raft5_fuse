//! `raft5fs`: see `commands`.

use clap::Parser;
use commands::{Cli, run};

mod commands;

fn main() {
    std::process::exit(run(Cli::parse()));
}
